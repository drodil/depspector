use std::cell::{Cell, RefCell};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use tree_sitter::{Language, Node, Parser};

fn get_javascript_language() -> Language {
  tree_sitter_javascript::LANGUAGE.into()
}

thread_local! {
  static PARSER: RefCell<Parser> = RefCell::new({
    let mut parser = Parser::new();
    let language = get_javascript_language();
    parser.set_language(&language).expect("Error loading JavaScript grammar");
    parser
  });
}

thread_local! {
  static AST_NODE_COUNTER: AtomicUsize = const { AtomicUsize::new(0) };
  static AST_LAST_LOG: Cell<usize> = const { Cell::new(0) };
}

fn reset_ast_counter() {
  AST_NODE_COUNTER.with(|c| c.store(0, Ordering::Relaxed));
  AST_LAST_LOG.with(|l| l.set(0));
}

fn inc_ast_counter() {
  AST_NODE_COUNTER.with(|c| {
    let prev = c.fetch_add(1, Ordering::Relaxed) + 1;
    AST_LAST_LOG.with(|last| {
      if prev - last.get() >= 20_000 {
        if log::log_enabled!(log::Level::Debug) {
          log::debug!("[AST] Progress: {prev} nodes visited");
        }
        last.set(prev);
      }
    });
  });
}

#[derive(Debug, Clone)]
pub struct CallInfo {
  pub callee_name: Option<String>,
  pub object_name: Option<String>,
  pub property_chain: Vec<String>,
  pub arguments: Vec<ArgInfo>,
  pub line: usize,
}

#[derive(Debug, Clone)]
pub enum ArgInfo {
  StringLiteral(String),
  TemplateLiteral(String),
  Identifier(String),
  MemberExpr { object: String, property: String },
  BinaryExpr,
  Other,
}

#[derive(Debug, Clone)]
pub struct MemberAccessInfo {
  pub object: String,
  pub properties: Vec<String>,
  pub line: usize,
}

#[derive(Debug, Clone)]
pub struct AssignInfo {
  pub target: AssignTarget,
  pub line: usize,
}

#[derive(Debug, Clone)]
pub enum AssignTarget {
  Property { object: String, property: String },
  ComputedProperty { object: String, property: String },
  Other,
}

#[derive(Debug, Clone)]
pub struct DestructureInfo {
  pub names: Vec<String>,
  pub source_object: String,
  pub source_property: Option<String>,
  pub line: usize,
}

#[derive(Debug, Clone)]
pub struct StringLiteralInfo {
  pub value: String,
  pub line: usize,
}

/// Pre-extracted AST events from a single parse.
/// This allows multiple analyzers to share the same parsed data.
#[derive(Debug, Clone, Default)]
pub struct ParsedAst {
  pub calls: Vec<CallInfo>,
  pub member_accesses: Vec<MemberAccessInfo>,
  pub assignments: Vec<AssignInfo>,
  pub destructures: Vec<DestructureInfo>,
  pub string_literals: Vec<StringLiteralInfo>,
}

impl ParsedAst {
  /// Parse source code once and extract all AST events.
  pub fn parse(code: &str) -> Option<Self> {
    reset_ast_counter();
    let start = Instant::now();

    let tree = PARSER.with(|parser| {
      let mut parser = parser.borrow_mut();
      parser.parse(code, None)
    });

    let tree = match tree {
      Some(tree) => tree,
      None => {
        log::debug!("[AST] Failed to parse code");
        return None;
      }
    };

    let mut parsed = ParsedAst::default();
    let root_node = tree.root_node();
    extract_all_events(root_node, code.as_bytes(), &mut parsed);

    let elapsed = start.elapsed();
    if log::log_enabled!(log::Level::Debug) {
      let count = AST_NODE_COUNTER.with(|c| c.load(Ordering::Relaxed));
      log::debug!(
        "[AST] Parsed: {count} nodes in {elapsed:?}, extracted {} calls, {} members, {} assigns, {} strings",
        parsed.calls.len(),
        parsed.member_accesses.len(),
        parsed.assignments.len(),
        parsed.string_literals.len()
      );
    }

    Some(parsed)
  }
}

fn extract_all_events(node: Node, source: &[u8], parsed: &mut ParsedAst) {
  inc_ast_counter();

  match node.kind() {
    "call_expression" => {
      if let Some(info) = extract_call_info(node, source) {
        parsed.calls.push(info);
      }
    }
    "new_expression" => {
      if let Some(info) = extract_new_call_info(node, source) {
        parsed.calls.push(info);
      }
    }
    "member_expression" | "subscript_expression" => {
      if let Some(info) = extract_member_access(node, source) {
        parsed.member_accesses.push(info);
      }
    }
    "assignment_expression" | "variable_declarator" => {
      if let Some(info) = extract_assign_info(node, source) {
        parsed.assignments.push(info);
      }
      if node.kind() == "variable_declarator" {
        if let Some(destructure_info) = extract_destructure_info(node, source) {
          parsed.destructures.push(destructure_info);
        }
      }
    }
    "string" | "template_string" => {
      let text = node_text(node, source);
      let cleaned = text.trim_matches(|c| c == '"' || c == '\'' || c == '`').to_string();
      parsed
        .string_literals
        .push(StringLiteralInfo { value: cleaned, line: node.start_position().row + 1 });
    }
    _ => {}
  }

  let mut cursor = node.walk();
  for child in node.children(&mut cursor) {
    extract_all_events(child, source, parsed);
  }
}

pub trait AstVisitor {
  fn visit_call(&mut self, _info: &CallInfo) {}
  fn visit_member_access(&mut self, _info: &MemberAccessInfo) {}
  fn visit_assign(&mut self, _info: &AssignInfo) {}
  fn visit_destructure(&mut self, _info: &DestructureInfo) {}
  fn visit_string_literal(&mut self, _value: &str, _line: usize) {}
}

pub fn walk_parsed_ast<V: AstVisitor>(parsed: &ParsedAst, visitor: &mut V) {
  for call in &parsed.calls {
    visitor.visit_call(call);
  }
  for member in &parsed.member_accesses {
    visitor.visit_member_access(member);
  }
  for assign in &parsed.assignments {
    visitor.visit_assign(assign);
  }
  for destructure in &parsed.destructures {
    visitor.visit_destructure(destructure);
  }
  for string_lit in &parsed.string_literals {
    visitor.visit_string_literal(&string_lit.value, string_lit.line);
  }
}

pub fn walk_ast<V: AstVisitor>(parsed_ast: Option<&ParsedAst>, source: &str, visitor: &mut V) {
  if let Some(parsed) = parsed_ast {
    walk_parsed_ast(parsed, visitor);
  } else if let Some(parsed) = ParsedAst::parse(source) {
    walk_parsed_ast(&parsed, visitor);
  }
}

pub fn try_parse_and_walk<V: AstVisitor>(code: &str, visitor: &mut V) -> bool {
  reset_ast_counter();
  let start = Instant::now();

  let tree = PARSER.with(|parser| {
    let mut parser = parser.borrow_mut();
    parser.parse(code, None)
  });

  let tree = match tree {
    Some(tree) => tree,
    None => {
      log::debug!("[AST] Failed to parse code");
      return false;
    }
  };

  let root_node = tree.root_node();
  walk_node(root_node, code.as_bytes(), visitor);

  let elapsed = start.elapsed();
  if log::log_enabled!(log::Level::Debug) {
    let count = AST_NODE_COUNTER.with(|c| c.load(Ordering::Relaxed));
    log::debug!("[AST] Finished: {count} nodes in {elapsed:?}");
  }

  true
}

fn walk_node<V: AstVisitor>(node: Node, source: &[u8], visitor: &mut V) {
  inc_ast_counter();

  match node.kind() {
    "call_expression" => {
      if let Some(info) = extract_call_info(node, source) {
        visitor.visit_call(&info);
      }
    }
    "new_expression" => {
      if let Some(info) = extract_new_call_info(node, source) {
        visitor.visit_call(&info);
      }
    }
    "member_expression" | "subscript_expression" => {
      if let Some(info) = extract_member_access(node, source) {
        visitor.visit_member_access(&info);
      }
    }
    "assignment_expression" | "variable_declarator" => {
      if let Some(info) = extract_assign_info(node, source) {
        visitor.visit_assign(&info);
      }
      // Also check for destructuring patterns
      if node.kind() == "variable_declarator" {
        if let Some(destructure_info) = extract_destructure_info(node, source) {
          visitor.visit_destructure(&destructure_info);
        }
      }
    }
    "string" | "template_string" => {
      let text = node_text(node, source);
      let cleaned = text.trim_matches(|c| c == '"' || c == '\'' || c == '`');
      visitor.visit_string_literal(cleaned, node.start_position().row + 1);
    }
    _ => {}
  }

  let mut cursor = node.walk();
  for child in node.children(&mut cursor) {
    walk_node(child, source, visitor);
  }
}

fn extract_call_info(node: Node, source: &[u8]) -> Option<CallInfo> {
  let function_node = node.child_by_field_name("function")?;
  let function_text = node_text(function_node, source);

  let (callee_name, object_name, property_chain) = parse_function_name(&function_text);

  let arguments = if let Some(args_node) = node.child_by_field_name("arguments") {
    extract_args(args_node, source)
  } else {
    Vec::new()
  };

  Some(CallInfo {
    line: node.start_position().row + 1,
    callee_name,
    object_name,
    property_chain,
    arguments,
  })
}

fn extract_new_call_info(node: Node, source: &[u8]) -> Option<CallInfo> {
  let ctor_node = node.child_by_field_name("constructor")?;
  let function_text = node_text(ctor_node, source);

  let (callee_name, object_name, property_chain) = parse_function_name(&function_text);

  let arguments = if let Some(args_node) = node.child_by_field_name("arguments") {
    extract_args(args_node, source)
  } else {
    Vec::new()
  };

  Some(CallInfo {
    line: node.start_position().row + 1,
    callee_name,
    object_name,
    property_chain,
    arguments,
  })
}

fn parse_function_name(text: &str) -> (Option<String>, Option<String>, Vec<String>) {
  let parts: Vec<&str> = text.split('.').collect();
  if parts.len() == 1 {
    (Some(parts[0].to_string()), None, Vec::new())
  } else if parts.len() == 2 {
    (Some(parts[1].to_string()), Some(parts[0].to_string()), vec![parts[1].to_string()])
  } else {
    let object_name = parts[0].to_string();
    let callee_name = parts.last().map(|s| s.to_string());
    let property_chain = parts[1..].iter().map(|s| s.to_string()).collect();
    (callee_name, Some(object_name), property_chain)
  }
}

fn extract_args(args_node: Node, source: &[u8]) -> Vec<ArgInfo> {
  let mut args = Vec::new();
  let mut cursor = args_node.walk();

  for child in args_node.children(&mut cursor) {
    if child.kind() == "," || child.kind() == "(" || child.kind() == ")" {
      continue;
    }
    args.push(extract_arg_info(child, source));
  }

  args
}

fn extract_arg_info(node: Node, source: &[u8]) -> ArgInfo {
  match node.kind() {
    "string" => {
      let text = node_text(node, source);
      ArgInfo::StringLiteral(text.trim_matches(|c| c == '"' || c == '\'').to_string())
    }
    "template_string" => {
      let text = node_text(node, source);
      ArgInfo::TemplateLiteral(text.trim_matches('`').to_string())
    }
    "identifier" => ArgInfo::Identifier(node_text(node, source)),
    "member_expression" => {
      if let Some(info) = extract_member_access(node, source) {
        ArgInfo::MemberExpr { object: info.object, property: info.properties.join(".") }
      } else {
        ArgInfo::Other
      }
    }
    "binary_expression" => ArgInfo::BinaryExpr,
    _ => ArgInfo::Other,
  }
}

fn extract_member_access(node: Node, source: &[u8]) -> Option<MemberAccessInfo> {
  let mut properties = Vec::new();
  let mut current = node;
  let mut object = String::new();

  loop {
    match current.kind() {
      "member_expression" | "subscript_expression" => {
        if current.kind() == "subscript_expression" {
          if let Some(index) = current.child_by_field_name("index") {
            let index_text = node_text(index, source);
            let cleaned = index_text.trim_matches(|c| c == '"' || c == '\'');
            properties.push(cleaned.to_string());
          }
        } else if let Some(property) = current.child_by_field_name("property") {
          properties.push(node_text(property, source));
        }
        if let Some(obj) = current.child_by_field_name("object") {
          current = obj;
        } else {
          break;
        }
      }
      "identifier" => {
        object = node_text(current, source);
        break;
      }
      _ => break,
    }
  }

  properties.reverse();

  if object.is_empty() && properties.is_empty() {
    return None;
  }

  Some(MemberAccessInfo { object, properties, line: node.start_position().row + 1 })
}

fn extract_assign_info(node: Node, source: &[u8]) -> Option<AssignInfo> {
  let (target_node, _value_node) = match node.kind() {
    "assignment_expression" => {
      let left = node.child_by_field_name("left")?;
      let right = node.child_by_field_name("right")?;
      (left, right)
    }
    "variable_declarator" => {
      let name = node.child_by_field_name("name")?;
      let value = node.child_by_field_name("value")?;
      (name, value)
    }
    _ => return None,
  };

  let target = match target_node.kind() {
    "member_expression" | "subscript_expression" => {
      if let Some(info) = extract_member_access(target_node, source) {
        let props_len = info.properties.len();
        if props_len == 0 {
          AssignTarget::Other
        } else {
          let property = info.properties[props_len - 1].clone();
          let object_prefix = if props_len > 1 {
            format!("{}.{}", info.object, info.properties[..props_len - 1].join("."))
          } else {
            info.object
          };

          if target_node.kind() == "subscript_expression" {
            AssignTarget::ComputedProperty { object: object_prefix, property }
          } else {
            AssignTarget::Property { object: object_prefix, property }
          }
        }
      } else {
        AssignTarget::Other
      }
    }
    "object_pattern" | "array_pattern" => {
      let names = extract_destructure_bindings(target_node, source);
      if names.is_empty() {
        return None;
      }

      return Some(AssignInfo { line: node.start_position().row + 1, target: AssignTarget::Other });
    }
    _ => AssignTarget::Other,
  };

  Some(AssignInfo { line: node.start_position().row + 1, target })
}

fn extract_destructure_bindings(node: Node, source: &[u8]) -> Vec<String> {
  let mut bindings = Vec::new();
  let mut cursor = node.walk();

  for child in node.children(&mut cursor) {
    match child.kind() {
      "identifier" => bindings.push(node_text(child, source)),
      "shorthand_property_identifier_pattern" => bindings.push(node_text(child, source)),
      "object_pattern" | "array_pattern" => {
        bindings.extend(extract_destructure_bindings(child, source));
      }
      _ => {}
    }
  }

  bindings
}

fn extract_destructure_info(node: Node, source: &[u8]) -> Option<DestructureInfo> {
  if node.kind() != "variable_declarator" {
    return None;
  }

  let name_node = node.child_by_field_name("name")?;
  if name_node.kind() != "object_pattern" && name_node.kind() != "array_pattern" {
    return None;
  }

  let value_node = node.child_by_field_name("value")?;

  let (source_object, source_property) = match value_node.kind() {
    "member_expression" | "subscript_expression" => {
      if let Some(info) = extract_member_access(value_node, source) {
        (info.object, info.properties.first().cloned())
      } else {
        (String::new(), None)
      }
    }
    "identifier" => (node_text(value_node, source), None),
    _ => (String::new(), None),
  };

  let names = extract_destructure_bindings(name_node, source);

  if names.is_empty() {
    return None;
  }

  Some(DestructureInfo {
    names,
    source_object,
    source_property,
    line: node.start_position().row + 1,
  })
}
fn node_text(node: Node, source: &[u8]) -> String {
  node.utf8_text(source).unwrap_or("").to_string()
}

#[cfg(test)]
mod tests {
  use super::*;

  struct TestVisitor {
    calls: Vec<CallInfo>,
  }

  impl AstVisitor for TestVisitor {
    fn visit_call(&mut self, info: &CallInfo) {
      self.calls.push(info.clone());
    }
  }

  #[test]
  fn test_parse_simple() {
    let code = "console.log('hello');";
    let mut visitor = TestVisitor { calls: Vec::new() };
    assert!(try_parse_and_walk(code, &mut visitor));
    assert_eq!(visitor.calls.len(), 1);
    assert_eq!(visitor.calls[0].callee_name, Some("log".to_string()));
    assert_eq!(visitor.calls[0].object_name, Some("console".to_string()));
  }

  #[test]
  fn test_parse_require() {
    let code = "const fs = require('fs');";
    let mut visitor = TestVisitor { calls: Vec::new() };
    assert!(try_parse_and_walk(code, &mut visitor));
    assert_eq!(visitor.calls.len(), 1);
    assert_eq!(visitor.calls[0].callee_name, Some("require".to_string()));
  }

  #[test]
  fn test_parse_member() {
    let code = "process.env.PATH";
    let mut visitor = TestVisitor { calls: Vec::new() };
    assert!(try_parse_and_walk(code, &mut visitor));
  }
}

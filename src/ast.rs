use std::cell::{Cell, RefCell};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use tree_sitter::{Language, Node, Parser};

fn get_javascript_language() -> Language {
  tree_sitter_javascript::LANGUAGE.into()
}

/// Flags to indicate which AST node types an analyzer is interested in.
/// This allows skipping extraction/iteration of unused node types for better performance.
#[derive(Debug, Clone, Copy, Default)]
pub struct NodeInterest {
  pub calls: bool,
  pub member_accesses: bool,
  pub assignments: bool,
  pub destructures: bool,
  pub string_literals: bool,
}

impl NodeInterest {
  pub const fn all() -> Self {
    Self {
      calls: true,
      member_accesses: true,
      assignments: true,
      destructures: true,
      string_literals: true,
    }
  }

  pub const fn none() -> Self {
    Self {
      calls: false,
      member_accesses: false,
      assignments: false,
      destructures: false,
      string_literals: false,
    }
  }

  pub const fn with_calls(mut self) -> Self {
    self.calls = true;
    self
  }

  pub const fn with_member_accesses(mut self) -> Self {
    self.member_accesses = true;
    self
  }

  pub const fn with_assignments(mut self) -> Self {
    self.assignments = true;
    self
  }

  pub const fn with_destructures(mut self) -> Self {
    self.destructures = true;
    self
  }

  pub const fn with_string_literals(mut self) -> Self {
    self.string_literals = true;
    self
  }
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
  /// Simple variable assignment like `const x = "value"` or `let x = "value"`
  Variable {
    name: String,
    value: Option<AssignValue>,
  },
  Property {
    object: String,
    property: String,
  },
  ComputedProperty {
    object: String,
    property: String,
  },
  Other,
}

/// The value being assigned (for simple cases we can track)
#[derive(Debug, Clone)]
pub enum AssignValue {
  /// A string literal value
  StringLiteral(String),
  /// A template literal (may have interpolations)
  TemplateLiteral(String),
  /// A number literal
  Number(String),
  /// A boolean literal
  Boolean(bool),
  /// Reference to another variable
  Identifier(String),
  /// Binary expression (e.g., string concatenation)
  BinaryExpr { left: Box<AssignValue>, op: String, right: Box<AssignValue> },
  /// Object literal with string properties
  ObjectLiteral(Vec<(String, AssignValue)>),
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
  /// Pre-built variable map for data flow analysis
  pub variable_map: VariableMap,
}

impl ParsedAst {
  /// Parse source code once and extract all AST events.
  /// Uses the default timeout (no timeout).
  pub fn parse(code: &str) -> Option<Self> {
    Self::parse_with_timeout(code, 0)
  }

  /// Parse source code with a configurable timeout in milliseconds.
  /// If timeout_ms is 0, no timeout is applied.
  pub fn parse_with_timeout(code: &str, timeout_ms: u64) -> Option<Self> {
    reset_ast_counter();
    let start = Instant::now();

    let tree = PARSER.with(|parser| {
      let mut parser = parser.borrow_mut();
      if timeout_ms > 0 {
        parser.set_timeout_micros(timeout_ms * 1000);
      } else {
        parser.set_timeout_micros(0);
      }
      let result = parser.parse(code, None);
      // Reset timeout after parsing
      parser.set_timeout_micros(0);
      result
    });

    let tree = match tree {
      Some(tree) => tree,
      None => {
        log::debug!("[AST] Failed to parse code (possibly timed out after {}ms)", timeout_ms);
        return None;
      }
    };

    let mut parsed = ParsedAst::default();
    let root_node = tree.root_node();
    extract_all_events(root_node, code.as_bytes(), &mut parsed);

    // Build the variable map once after extracting all assignments
    parsed.variable_map = parsed.build_variable_map_internal();

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

  /// Build a map of variable names to their string values.
  /// This enables simple data flow analysis to resolve identifiers in function calls.
  fn build_variable_map_internal(&self) -> VariableMap {
    let mut var_map = std::collections::HashMap::new();
    let mut obj_map: std::collections::HashMap<String, Vec<(String, String)>> =
      std::collections::HashMap::new();

    for assign in &self.assignments {
      match &assign.target {
        AssignTarget::Variable { name, value: Some(value) } => {
          if let Some(resolved) = self.resolve_assign_value(value, &var_map) {
            var_map.insert(name.clone(), resolved);
          }
          // Also track object literals for property access
          if let AssignValue::ObjectLiteral(props) = value {
            let mut resolved_props = Vec::new();
            for (key, val) in props {
              if let Some(resolved) = self.resolve_assign_value(val, &var_map) {
                resolved_props.push((key.clone(), resolved));
              }
            }
            if !resolved_props.is_empty() {
              obj_map.insert(name.clone(), resolved_props);
            }
          }
        }
        AssignTarget::Property { object, property: _ } => {
          // Track obj.prop = "value" assignments
          if let Some(AssignTarget::Variable { value: Some(value), .. }) = self
            .assignments
            .iter()
            .find(|a| matches!(&a.target, AssignTarget::Variable { name, .. } if name == object))
            .map(|a| &a.target)
          {
            // Object exists, ignore for now - we track at declaration time
            let _ = value;
          }
        }
        _ => {}
      }
    }

    VariableMap { var_map, obj_map }
  }

  /// Resolve an AssignValue to a string
  fn resolve_assign_value(
    &self,
    value: &AssignValue,
    current_map: &std::collections::HashMap<String, String>,
  ) -> Option<String> {
    match value {
      AssignValue::StringLiteral(s) => Some(s.clone()),
      AssignValue::TemplateLiteral(s) => Some(self.resolve_template_interpolations(s, current_map)),
      AssignValue::Identifier(other_var) => current_map.get(other_var).cloned(),
      AssignValue::BinaryExpr { left, op, right } if op == "+" => {
        let left_val = self.resolve_assign_value(left, current_map)?;
        let right_val = self.resolve_assign_value(right, current_map)?;
        Some(format!("{}{}", left_val, right_val))
      }
      _ => None,
    }
  }

  /// Resolve simple ${var} interpolations in template literals
  fn resolve_template_interpolations(
    &self,
    template: &str,
    current_map: &std::collections::HashMap<String, String>,
  ) -> String {
    use regex::Regex;
    lazy_static::lazy_static! {
      static ref INTERPOLATION_RE: Regex = Regex::new(r"\$\{([a-zA-Z_][a-zA-Z0-9_]*)\}").unwrap();
    }

    let mut result = template.to_string();
    for cap in INTERPOLATION_RE.captures_iter(template) {
      let full_match = &cap[0];
      let var_name = &cap[1];
      if let Some(value) = current_map.get(var_name) {
        result = result.replace(full_match, value);
      }
    }
    result
  }
}

/// A map of variable names to their resolved string values.
/// Used for simple intra-file data flow analysis.
#[derive(Debug, Clone, Default)]
pub struct VariableMap {
  var_map: std::collections::HashMap<String, String>,
  obj_map: std::collections::HashMap<String, Vec<(String, String)>>,
}

impl VariableMap {
  /// Resolve an ArgInfo to a string value if possible.
  /// Returns the resolved value for StringLiteral, TemplateLiteral, Identifier, or MemberExpr (if in map).
  pub fn resolve_arg(&self, arg: &ArgInfo) -> Option<String> {
    match arg {
      ArgInfo::StringLiteral(s) | ArgInfo::TemplateLiteral(s) => Some(s.clone()),
      ArgInfo::Identifier(name) => self.var_map.get(name).cloned(),
      ArgInfo::MemberExpr { object, property } => {
        // Try to resolve obj.prop access
        if let Some(props) = self.obj_map.get(object) {
          for (key, value) in props {
            if key == property {
              return Some(value.clone());
            }
          }
        }
        None
      }
      _ => None,
    }
  }

  /// Check if a variable name is in the map.
  pub fn contains(&self, name: &str) -> bool {
    self.var_map.contains_key(name)
  }

  /// Get the value of a variable by name.
  pub fn get(&self, name: &str) -> Option<&String> {
    self.var_map.get(name)
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
  walk_parsed_ast_filtered(parsed, visitor, NodeInterest::all());
}

/// Walk the pre-parsed AST, only visiting node types specified in `interest`.
/// This is more efficient when an analyzer only needs specific node types.
pub fn walk_parsed_ast_filtered<V: AstVisitor>(
  parsed: &ParsedAst,
  visitor: &mut V,
  interest: NodeInterest,
) {
  if interest.calls {
    for call in &parsed.calls {
      visitor.visit_call(call);
    }
  }
  if interest.member_accesses {
    for member in &parsed.member_accesses {
      visitor.visit_member_access(member);
    }
  }
  if interest.assignments {
    for assign in &parsed.assignments {
      visitor.visit_assign(assign);
    }
  }
  if interest.destructures {
    for destructure in &parsed.destructures {
      visitor.visit_destructure(destructure);
    }
  }
  if interest.string_literals {
    for string_lit in &parsed.string_literals {
      visitor.visit_string_literal(&string_lit.value, string_lit.line);
    }
  }
}

pub fn walk_ast<V: AstVisitor>(parsed_ast: Option<&ParsedAst>, source: &str, visitor: &mut V) {
  walk_ast_filtered(parsed_ast, source, visitor, NodeInterest::all());
}

/// Walk the AST, only visiting node types specified in `interest`.
/// If a pre-parsed AST is provided, it will be used; otherwise parses from source.
pub fn walk_ast_filtered<V: AstVisitor>(
  parsed_ast: Option<&ParsedAst>,
  source: &str,
  visitor: &mut V,
  interest: NodeInterest,
) {
  if let Some(parsed) = parsed_ast {
    walk_parsed_ast_filtered(parsed, visitor, interest);
  } else if let Some(parsed) = ParsedAst::parse(source) {
    walk_parsed_ast_filtered(&parsed, visitor, interest);
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
  let (target_node, value_node) = match node.kind() {
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
    // Simple variable: const x = "value" or x = "value"
    "identifier" => {
      let name = node_text(target_node, source);
      let value = extract_assign_value(value_node, source);
      AssignTarget::Variable { name, value }
    }
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

/// Extract the value from an assignment's right-hand side.
fn extract_assign_value(node: Node, source: &[u8]) -> Option<AssignValue> {
  match node.kind() {
    "string" => {
      let text = node_text(node, source);
      // Remove quotes
      let value = text.trim_matches(|c| c == '"' || c == '\'' || c == '`');
      Some(AssignValue::StringLiteral(value.to_string()))
    }
    "template_string" => {
      let text = node_text(node, source);
      // Remove backticks
      let value = text.trim_start_matches('`').trim_end_matches('`');
      Some(AssignValue::TemplateLiteral(value.to_string()))
    }
    "number" => {
      let text = node_text(node, source);
      Some(AssignValue::Number(text))
    }
    "true" => Some(AssignValue::Boolean(true)),
    "false" => Some(AssignValue::Boolean(false)),
    "identifier" => {
      let name = node_text(node, source);
      Some(AssignValue::Identifier(name))
    }
    "binary_expression" => {
      let left = node.child_by_field_name("left")?;
      let right = node.child_by_field_name("right")?;
      let op =
        node.child_by_field_name("operator").map(|n| node_text(n, source)).unwrap_or_default();

      let left_val = extract_assign_value(left, source)?;
      let right_val = extract_assign_value(right, source)?;

      Some(AssignValue::BinaryExpr { left: Box::new(left_val), op, right: Box::new(right_val) })
    }
    "object" => {
      let mut props = Vec::new();
      let mut cursor = node.walk();

      for child in node.children(&mut cursor) {
        if child.kind() == "pair" {
          if let (Some(key_node), Some(value_node)) =
            (child.child_by_field_name("key"), child.child_by_field_name("value"))
          {
            let key = match key_node.kind() {
              "property_identifier" | "string" => {
                let k = node_text(key_node, source);
                k.trim_matches(|c| c == '"' || c == '\'').to_string()
              }
              _ => continue,
            };

            if let Some(val) = extract_assign_value(value_node, source) {
              props.push((key, val));
            }
          }
        }
      }

      if props.is_empty() {
        None
      } else {
        Some(AssignValue::ObjectLiteral(props))
      }
    }
    _ => None,
  }
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
    strings: Vec<String>,
    members: Vec<MemberAccessInfo>,
  }

  impl AstVisitor for TestVisitor {
    fn visit_call(&mut self, info: &CallInfo) {
      self.calls.push(info.clone());
    }

    fn visit_string_literal(&mut self, value: &str, _line: usize) {
      self.strings.push(value.to_string());
    }

    fn visit_member_access(&mut self, info: &MemberAccessInfo) {
      self.members.push(info.clone());
    }
  }

  #[test]
  fn test_parse_simple() {
    let code = "console.log('hello');";
    let mut visitor = TestVisitor { calls: Vec::new(), strings: Vec::new(), members: Vec::new() };
    assert!(try_parse_and_walk(code, &mut visitor));
    assert_eq!(visitor.calls.len(), 1);
    assert_eq!(visitor.calls[0].callee_name, Some("log".to_string()));
    assert_eq!(visitor.calls[0].object_name, Some("console".to_string()));
  }

  #[test]
  fn test_parse_require() {
    let code = "const fs = require('fs');";
    let mut visitor = TestVisitor { calls: Vec::new(), strings: Vec::new(), members: Vec::new() };
    assert!(try_parse_and_walk(code, &mut visitor));
    assert_eq!(visitor.calls.len(), 1);
    assert_eq!(visitor.calls[0].callee_name, Some("require".to_string()));
  }

  #[test]
  fn test_parse_member() {
    let code = "process.env.PATH";
    let mut visitor = TestVisitor { calls: Vec::new(), strings: Vec::new(), members: Vec::new() };
    assert!(try_parse_and_walk(code, &mut visitor));
  }

  #[test]
  fn test_node_interest_filters_calls_only() {
    let code = r#"
      console.log('hello');
      const x = process.env.FOO;
    "#;
    let parsed = ParsedAst::parse(code).unwrap();

    assert!(!parsed.calls.is_empty());
    assert!(!parsed.string_literals.is_empty());
    assert!(!parsed.member_accesses.is_empty());

    let mut visitor = TestVisitor { calls: Vec::new(), strings: Vec::new(), members: Vec::new() };
    let interest = NodeInterest::none().with_calls();
    walk_parsed_ast_filtered(&parsed, &mut visitor, interest);

    assert!(!visitor.calls.is_empty());
    assert!(visitor.strings.is_empty()); // Should not be visited
    assert!(visitor.members.is_empty()); // Should not be visited
  }

  #[test]
  fn test_node_interest_filters_strings_only() {
    let code = r#"
      const url = "https://example.com";
      fetch(url);
    "#;
    let parsed = ParsedAst::parse(code).unwrap();

    let mut visitor = TestVisitor { calls: Vec::new(), strings: Vec::new(), members: Vec::new() };
    let interest = NodeInterest::none().with_string_literals();
    walk_parsed_ast_filtered(&parsed, &mut visitor, interest);

    assert!(visitor.calls.is_empty()); // Should not be visited
    assert!(!visitor.strings.is_empty());
  }

  #[test]
  fn test_node_interest_all() {
    let code = r#"
      console.log('hello');
      const x = obj.prop;
    "#;
    let parsed = ParsedAst::parse(code).unwrap();

    let mut visitor = TestVisitor { calls: Vec::new(), strings: Vec::new(), members: Vec::new() };
    walk_parsed_ast_filtered(&parsed, &mut visitor, NodeInterest::all());

    assert!(!visitor.calls.is_empty());
    assert!(!visitor.strings.is_empty());
    assert!(!visitor.members.is_empty());
  }

  #[test]
  fn test_variable_map_simple_string() {
    let code = r#"
      const path = '/etc/passwd';
      fs.readFile(path);
    "#;
    let parsed = ParsedAst::parse(code).unwrap();

    assert_eq!(parsed.variable_map.get("path"), Some(&"/etc/passwd".to_string()));
  }

  #[test]
  fn test_variable_map_template_literal() {
    let code = r#"
      const url = `http://example.com`;
      fetch(url);
    "#;
    let parsed = ParsedAst::parse(code).unwrap();

    assert_eq!(parsed.variable_map.get("url"), Some(&"http://example.com".to_string()));
  }

  #[test]
  fn test_variable_map_resolve_arg() {
    let code = r#"
      const target = '/etc/shadow';
      const x = target;
    "#;
    let parsed = ParsedAst::parse(code).unwrap();

    // Direct resolve
    let arg = ArgInfo::Identifier("target".to_string());
    assert_eq!(parsed.variable_map.resolve_arg(&arg), Some("/etc/shadow".to_string()));

    // String literal passthrough
    let arg2 = ArgInfo::StringLiteral("/etc/passwd".to_string());
    assert_eq!(parsed.variable_map.resolve_arg(&arg2), Some("/etc/passwd".to_string()));

    // Unknown variable
    let arg3 = ArgInfo::Identifier("unknown".to_string());
    assert_eq!(parsed.variable_map.resolve_arg(&arg3), None);
  }

  #[test]
  fn test_variable_map_transitive() {
    let code = r#"
      const a = '/etc/passwd';
      const b = a;
    "#;
    let parsed = ParsedAst::parse(code).unwrap();

    // b should resolve to /etc/passwd through a
    assert_eq!(parsed.variable_map.get("b"), Some(&"/etc/passwd".to_string()));
  }

  #[test]
  fn test_variable_map_let_assignment() {
    let code = r#"
      let path;
      path = '/etc/passwd';
    "#;
    let parsed = ParsedAst::parse(code).unwrap();

    assert_eq!(parsed.variable_map.get("path"), Some(&"/etc/passwd".to_string()));
  }

  #[test]
  fn test_variable_map_template_interpolation() {
    let code = r#"
      const base = '/etc';
      const path = `${base}/passwd`;
    "#;
    let parsed = ParsedAst::parse(code).unwrap();

    assert_eq!(parsed.variable_map.get("path"), Some(&"/etc/passwd".to_string()));
  }

  #[test]
  fn test_variable_map_multiple_interpolations() {
    let code = r#"
      const host = 'example.com';
      const path = '/api';
      const url = `https://${host}${path}`;
    "#;
    let parsed = ParsedAst::parse(code).unwrap();

    assert_eq!(parsed.variable_map.get("url"), Some(&"https://example.com/api".to_string()));
  }

  #[test]
  fn test_variable_map_string_concatenation() {
    let code = r#"
      const path = '/etc' + '/passwd';
    "#;
    let parsed = ParsedAst::parse(code).unwrap();

    assert_eq!(parsed.variable_map.get("path"), Some(&"/etc/passwd".to_string()));
  }

  #[test]
  fn test_variable_map_concat_with_variable() {
    let code = r#"
      const base = '/etc';
      const path = base + '/passwd';
    "#;
    let parsed = ParsedAst::parse(code).unwrap();

    assert_eq!(parsed.variable_map.get("path"), Some(&"/etc/passwd".to_string()));
  }

  #[test]
  fn test_variable_map_object_property() {
    let code = r#"
      const config = { path: '/etc/passwd', host: 'localhost' };
      fs.readFile(config.path);
    "#;
    let parsed = ParsedAst::parse(code).unwrap();

    // Test direct property lookup
    let arg = ArgInfo::MemberExpr { object: "config".to_string(), property: "path".to_string() };
    assert_eq!(parsed.variable_map.resolve_arg(&arg), Some("/etc/passwd".to_string()));

    let arg2 = ArgInfo::MemberExpr { object: "config".to_string(), property: "host".to_string() };
    assert_eq!(parsed.variable_map.resolve_arg(&arg2), Some("localhost".to_string()));
  }

  #[test]
  fn test_variable_map_nested_concat() {
    let code = r#"
      const a = '/etc';
      const b = a + '/';
      const c = b + 'passwd';
    "#;
    let parsed = ParsedAst::parse(code).unwrap();

    assert_eq!(parsed.variable_map.get("c"), Some(&"/etc/passwd".to_string()));
  }
}

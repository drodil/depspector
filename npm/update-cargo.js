/**
 * Custom updater for standard-version to update Cargo.toml version field.
 * Used by .versionrc.json to bump the Rust crate version alongside npm packages.
 */

const VERSION_REGEX = /^version\s*=\s*"([^"]+)"/m;

module.exports.readVersion = function (contents) {
  const match = contents.match(VERSION_REGEX);
  if (!match) {
    throw new Error('Could not find version in Cargo.toml');
  }
  return match[1];
};

module.exports.writeVersion = function (contents, version) {
  return contents.replace(VERSION_REGEX, `version = "${version}"`);
};

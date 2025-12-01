#!/usr/bin/env node

const cli = require("./index");
const args = process.argv.slice(2);

cli.run(args).catch((e) => {
  console.error(e);
  process.exit(1);
});

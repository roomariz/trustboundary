#!/usr/bin/env node

const { spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");

function findPython() {
  const candidates = process.platform === "win32" ? ["python"] : ["python3", "python"];
  for (const command of candidates) {
    const result = spawnSync(command, ["--version"], { stdio: "ignore" });
    if (!result.error && result.status === 0) {
      return command;
    }
  }
  return null;
}

function main() {
  const argv = process.argv.slice(2);
  const maybeSubcommand = argv[0];
  const scanArgs = maybeSubcommand === "scan" ? argv.slice(1) : argv;
  const python = findPython();
  if (!python) {
    console.error("repo-security-audit requires Python 3, but no Python executable was found on PATH.");
    process.exit(1);
  }

  const scriptPath = path.resolve(__dirname, "..", "scripts", "run_audit.py");
  if (!fs.existsSync(scriptPath)) {
    console.error(`Cannot find audit script: ${scriptPath}`);
    process.exit(1);
  }

  const result = spawnSync(python, [scriptPath, ...scanArgs], {
    stdio: "inherit",
  });

  if (result.error) {
    console.error(result.error.message);
    process.exit(1);
  }

  process.exit(typeof result.status === "number" ? result.status : 1);
}

main();

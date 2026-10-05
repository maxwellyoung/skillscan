#!/usr/bin/env node
import { run } from './run';

const color = Boolean(process.stdout.isTTY) && !('NO_COLOR' in process.env);

run(process.argv.slice(2), {
  stdout: text => process.stdout.write(text),
  stderr: text => process.stderr.write(text),
  color,
}).then(
  code => {
    process.exitCode = code;
  },
  error => {
    process.stderr.write(`skillscan: ${error instanceof Error ? error.stack ?? error.message : String(error)}\n`);
    process.exitCode = 2;
  },
);

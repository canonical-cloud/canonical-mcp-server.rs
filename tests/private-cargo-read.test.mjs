import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const read = async (path) => {
  return await readFile(new URL(`../${path}`, import.meta.url), 'utf8');
};

test('private Cargo helper is fail-closed and process-local', async () => {
  const helper = await read('scripts/cargo-private-read.sh');

  assert.match(helper, /CANONICAL_LIB_READ_TOKEN/);
  assert.match(helper, /CARGO_NET_GIT_FETCH_WITH_CLI=true/);
  assert.match(helper, /GIT_TERMINAL_PROMPT=0/);
  assert.match(helper, /GIT_CONFIG_COUNT=1/);
  assert.match(helper, /insteadOf/);
  assert.doesNotMatch(helper, /git config --global/);
});

test('networked Cargo CI steps use only the scoped read credential', async () => {
  const workflow = await read('.github/workflows/ci.yml');

  assert.match(workflow, /persist-credentials: false/);
  assert.match(workflow, /CANONICAL_LIB_READ_TOKEN: \$\{\{ secrets\.CANONICAL_LIB_READ_TOKEN \}\}/);
  assert.match(workflow, /cargo-private-read\.sh clippy --locked --all-targets/);
  assert.match(workflow, /cargo-private-read\.sh test --locked --all-targets/);
  assert.match(workflow, /cargo-private-read\.sh build --locked --release/);
  assert.doesNotMatch(workflow, /permissions:\s*[\s\S]*?contents: write/);
});

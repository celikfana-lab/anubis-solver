/**
 * Exercises the plugin contract the way the harness calls it: `apply(ctx)` with a
 * stub context, then the registered tool's `execute` and `render`. No DSH
 * packages needed, so it runs anywhere.
 *
 *   node --test dsh-plugin/test.mjs        (or: node dsh-plugin/test.mjs)
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';

import { apply, inject, name } from './index.js';

const REPO = new URL('..', import.meta.url).pathname;

function stubContext() {
  const registered = [];
  const sections = [];
  const ctx = {
    tools: {
      register(definition, options) {
        registered.push({ definition, options });
        return () => {};
      },
      get: (n) => registered.find((r) => r.definition.name === n)?.definition,
    },
    systemPrompt: {
      // mirrors the harness: a section needs a finite numeric order
      getSectionOrder: (n) => (n === 'TOOL_WEB_FETCH' ? 2100 : 0),
      section(s) {
        sections.push(s);
      },
    },
  };
  return { ctx, registered, sections };
}

test('plugin declares its name and required services', () => {
  assert.equal(name, 'anubis-fetch');
  assert.deepEqual(inject, ['tools', 'systemPrompt']);
});

test('apply registers one tool with a model-facing schema and a prompt note', () => {
  const { ctx, registered, sections } = stubContext();
  apply(ctx, {});

  assert.equal(registered.length, 1);
  const tool = registered[0].definition;
  assert.equal(tool.name, 'anubis_fetch');
  assert.ok(tool.description.length > 40, 'description should explain when to use it');
  assert.equal(tool.parameters.type, 'object');
  assert.deepEqual(tool.parameters.required, ['url']);
  assert.equal(tool.parameters.properties.url.type, 'string');
  assert.ok(tool.timeoutMs > 0);
  assert.equal(typeof tool.execute, 'function');
  assert.equal(typeof tool.output.render, 'function');

  const declared = Object.keys(tool.output.schema.properties).sort();
  assert.deepEqual(declared, [
    'challenge', 'content', 'finalUrl', 'statusCode', 'stillChallenged', 'title', 'truncated', 'url',
  ]);
  assert.equal(tool.output.schema.required.length, declared.length);

  assert.equal(sections.length, 1);
  assert.equal(sections[0].name, 'tool:anubis_fetch');
  assert.ok(Number.isFinite(sections[0].order), 'prompt section needs a finite order');
  assert.ok(sections[0].order > 0);
  assert.match(sections[0].text({ scope: {}, toolSet: {} }), /untrusted/i);
});

test('a non-http url is rejected before spawning anything', async () => {
  const { ctx, registered } = stubContext();
  apply(ctx, {});
  const tool = registered[0].definition;
  await assert.rejects(() => tool.execute({ url: 'file:///etc/passwd' }, {}), /http\(s\) URL/);
});

test('execute solves a real Anubis challenge and render shows it', async () => {
  const { ctx, registered } = stubContext();
  apply(ctx, { repo: REPO, python: 'python3', timeoutMs: 60000 });

  const tool = registered[0].definition;
  const value = await tool.execute({ url: 'https://anubis.techaro.lol/', maxChars: 4000 }, {});

  // the value must satisfy the declared output schema's required keys
  for (const key of tool.output.schema.required) {
    assert.ok(key in value, `missing output key ${key}`);
  }
  assert.equal(value.statusCode, 200);
  assert.match(value.url, /^https:\/\/anubis\.techaro\.lol\//);
  assert.ok(value.challenge !== null, 'expected a challenge to have been solved');

  const c = value.challenge;
  assert.ok(
    ['fast', 'slow', 'sha256', 'argon2id', 'hashx', 'metarefresh'].includes(c.algorithm),
    `algorithm ${c.algorithm}`,
  );
  assert.ok(Number.isInteger(c.difficulty) && c.difficulty > 0);
  if (c.algorithm !== 'metarefresh') assert.ok(Number.isInteger(c.nonce) && c.nonce >= 0);
  if (c.algorithm !== 'metarefresh') assert.match(c.response, /^[0-9a-f]{64}$/);
  assert.ok(c.elapsedMs >= 0);

  assert.equal(value.stillChallenged, false, 'the returned body must not still be the challenge page');
  assert.match(value.title, /Anubis/i);
  assert.ok(value.content.length > 100, 'expected real page text');

  const blocks = tool.output.render({ url: value.url }, value);
  assert.equal(blocks.length, 1);
  assert.equal(blocks[0].type, 'text');
  assert.match(blocks[0].text, /untrusted/i);
  // metarefresh is "passed", the PoW algorithms are "solved"
  assert.match(blocks[0].text, new RegExp(`Anubis challenge (solved|passed) locally: ${c.algorithm}`));
  assert.doesNotMatch(blocks[0].text, /undefined/);
  assert.ok(blocks[0].text.includes(value.content.slice(0, 80)));

  console.log(`    solved ${c.algorithm}/${c.difficulty}: nonce ${c.nonce} in ${c.elapsedMs} ms, ` +
              `${value.content.length} chars of "${value.title}"`);
});

test('engine "js" solves without ever touching the Python driver', async () => {
  const { ctx, registered } = stubContext();
  // a repo with the JS engine but no .py driver at all: if this passes, the
  // Python path was never taken
  apply(ctx, { repo: REPO, engine: 'js', python: '/nonexistent/python' });
  const tool = registered[0].definition;
  const value = await tool.execute({ url: 'https://anubis.techaro.lol/', maxChars: 2000 }, {});
  assert.equal(value.statusCode, 200);
  assert.ok(value.challenge !== null);
  assert.ok(value.content.length > 50);
});

test('a missing driver is reported, not swallowed', async () => {
  const { ctx, registered } = stubContext();
  apply(ctx, { repo: '/nonexistent-repo', python: 'python3' });
  const tool = registered[0].definition;
  await assert.rejects(() => tool.execute({ url: 'https://example.com/' }, {}), /driver not found/);
});

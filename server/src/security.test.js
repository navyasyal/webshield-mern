import test from 'node:test';import assert from 'node:assert/strict';
import {validateLabUrl} from './security.js';
test('lab allowed',()=>assert.equal(validateLabUrl('http://lab:4000/'),'http://lab:4000/'));
test('public targets denied',()=>assert.throws(()=>validateLabUrl('https://example.com')));
test('credentialed URLs denied',()=>assert.throws(()=>validateLabUrl('http://u:p@lab:4000')));

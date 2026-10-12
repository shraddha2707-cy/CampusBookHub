const test = require('node:test');
const assert = require('node:assert/strict');
const { checkMessage, MODERATION_WARNING } = require('../moderation/profanityFilter');

test('allows ordinary marketplace conversation', () => {
    [
        'Is the book still available?',
        'Can you reduce the price?',
        'Where can I collect the book?'
    ].forEach(message => assert.deepEqual(checkMessage(message), { allowed: true }));
});

test('blocks prohibited words and phrases without matching parts of normal words', () => {
    [
        'That is bullshit.',
        'FUCK you',
        'You are a bitch',
        'I hate you',
        'You are an idiot',
        'Watch your back',
        'I will punch you',
        'I will hurt you',
        'send nudes'
    ].forEach(message => assert.equal(checkMessage(message).allowed, false, message));

    [
        'The classic book is in a glass case.',
        'The assistant is in class.',
        'This is a hell of a good book.'
    ].forEach(message => assert.equal(checkMessage(message).allowed, true, message));
});

test('normalizes case, whitespace, punctuation, repeated letters, and common substitutions', () => {
    [
        'F U C K',
        'f.u.c.k',
        'fuuuuuck',
        '$h1t',
        'b!tch',
        'h\u200Bate you'
    ].forEach(message => assert.equal(checkMessage(message).allowed, false, message));
});

test('supports long messages and independent concurrent checks', async () => {
    const longSafeMessage = `Is the book available? ${'Please let me know. '.repeat(60)}`;
    assert.ok(longSafeMessage.length > 1000);
    assert.equal(checkMessage(longSafeMessage).allowed, true);

    const results = await Promise.all([
        Promise.resolve(checkMessage('Can you reduce the price?')),
        Promise.resolve(checkMessage('fuck you')),
        Promise.resolve(checkMessage('Where can I collect the book?')),
        Promise.resolve(checkMessage('kill yourself'))
    ]);
    assert.deepEqual(results.map(result => result.allowed), [true, false, true, false]);
});

test('returns a moderation outcome and sender warning text', () => {
    assert.deepEqual(checkMessage('shit'), { allowed: false, code: 'INAPPROPRIATE_LANGUAGE' });
    assert.equal(
        MODERATION_WARNING,
        'This message cannot be sent because it contains inappropriate or offensive language.'
    );
    assert.equal(checkMessage(null).code, 'INVALID_MESSAGE');
});

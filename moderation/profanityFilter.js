const bannedWords = require('./bannedWords');

const MODERATION_WARNING = 'This message cannot be sent because it contains inappropriate or offensive language.';
const LEET_SUBSTITUTIONS = Object.freeze({
    '@': 'a',
    '$': 's',
    '0': 'o',
    '1': 'i',
    '!': 'i',
    '3': 'e',
    '4': 'a',
    '5': 's',
    '7': 't',
    '8': 'b',
    '9': 'g'
});

function normalizeMessage(message) {
    return message
        .normalize('NFKD')
        .replace(/\p{M}/gu, '')
        .replace(/[\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF]/g, '')
        .toLowerCase()
        .replace(/[@$01345789!]/g, character => LEET_SUBSTITUTIONS[character]);
}

function escapeRegExp(character) {
    return character.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function wordPattern(word) {
    return Array.from(word, character => `${escapeRegExp(character)}+`)
        .join('[\\s\\p{P}\\p{S}]*');
}

const prohibitedPatterns = bannedWords.map(phrase => {
    const pattern = phrase.split(/\s+/).map(wordPattern).join('[\\s\\p{P}\\p{S}]+');
    return new RegExp(`(?<![\\p{L}\\p{N}])${pattern}(?![\\p{L}\\p{N}])`, 'u');
});

function checkMessage(message) {
    if (typeof message !== 'string') {
        return { allowed: false, code: 'INVALID_MESSAGE' };
    }

    const normalized = normalizeMessage(message);
    if (prohibitedPatterns.some(pattern => pattern.test(normalized))) {
        return { allowed: false, code: 'INAPPROPRIATE_LANGUAGE' };
    }

    return { allowed: true };
}

module.exports = { checkMessage, MODERATION_WARNING };

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { checkMessage, MODERATION_WARNING } = require('./moderation/profanityFilter');

const PORT = Number(process.env.PORT) || 3000;
const ROOT = __dirname;
const USERS_FILE = path.join(ROOT, 'users.json');
const LISTINGS_FILE = path.join(ROOT, 'listings.json');
const SESSIONS_FILE = path.join(ROOT, 'sessions.json');
const MESSAGES_FILE = path.join(ROOT, 'messages.json');
const UPLOADS_FILE = path.join(ROOT, 'uploads.json');
const WISHLISTS_FILE = path.join(ROOT, 'wishlists.json');
const PURCHASES_FILE = path.join(ROOT, 'purchases.json');
const RESTRICTIONS_FILE = path.join(ROOT, 'restrictions.json');
const sessions = new Map();
const rateLimitBuckets = new Map();
const SESSION_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_REQUEST_BODY_BYTES = 32 * 1024 * 1024;

function writeJson(filePath, value) {
    const temporaryPath = `${filePath}.${process.pid}.${crypto.randomUUID()}.tmp`;
    try {
        fs.writeFileSync(temporaryPath, `${JSON.stringify(value, null, 2)}\n`, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
        fs.renameSync(temporaryPath, filePath);
    } catch (error) {
        try {
            if (fs.existsSync(temporaryPath)) fs.unlinkSync(temporaryPath);
        } catch {}
        throw error;
    }
}

function hashSessionToken(token) {
    return crypto.createHash('sha256').update(token).digest('hex');
}

const MIME_TYPES = {
    '.html': 'text/html; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.ico': 'image/x-icon'
};
const UPLOAD_MIME_TYPES = {
    '.pdf': 'application/pdf',
    '.doc': 'application/msword',
    '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    '.txt': 'text/plain',
    '.ppt': 'application/vnd.ms-powerpoint',
    '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation'
};
const PUBLIC_FILE_EXTENSIONS = new Set(Object.keys(MIME_TYPES));

function readUsers() {
    if (!fs.existsSync(USERS_FILE)) {
        fs.writeFileSync(USERS_FILE, '[]\n', 'utf8');
    }
    return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
}

function writeUsers(users) {
    writeJson(USERS_FILE, users);
}

function readListings() {
    if (!fs.existsSync(LISTINGS_FILE)) {
        fs.writeFileSync(LISTINGS_FILE, '[]\n', 'utf8');
    }
    return JSON.parse(fs.readFileSync(LISTINGS_FILE, 'utf8'));
}

function writeListings(listings) {
    writeJson(LISTINGS_FILE, listings);
}

function readMessages() {
    if (!fs.existsSync(MESSAGES_FILE)) fs.writeFileSync(MESSAGES_FILE, '[]\n', 'utf8');
    return JSON.parse(fs.readFileSync(MESSAGES_FILE, 'utf8'));
}

function writeMessages(messages) {
    writeJson(MESSAGES_FILE, messages);
}

function readRestrictions() {
    if (!fs.existsSync(RESTRICTIONS_FILE)) return [];
    return JSON.parse(fs.readFileSync(RESTRICTIONS_FILE, 'utf8'));
}

function writeRestrictions(restrictions) {
    writeJson(RESTRICTIONS_FILE, restrictions);
}

function readUploads() {
    if (!fs.existsSync(UPLOADS_FILE)) fs.writeFileSync(UPLOADS_FILE, '[]\n', 'utf8');
    return JSON.parse(fs.readFileSync(UPLOADS_FILE, 'utf8'));
}

function writeUploads(uploads) {
    writeJson(UPLOADS_FILE, uploads);
}

function readWishlists() {
    if (!fs.existsSync(WISHLISTS_FILE)) fs.writeFileSync(WISHLISTS_FILE, '[]\n', 'utf8');
    return JSON.parse(fs.readFileSync(WISHLISTS_FILE, 'utf8'));
}

function writeWishlists(wishlists) {
    writeJson(WISHLISTS_FILE, wishlists);
}

function readPurchases() {
    if (!fs.existsSync(PURCHASES_FILE)) fs.writeFileSync(PURCHASES_FILE, '[]\n', 'utf8');
    return JSON.parse(fs.readFileSync(PURCHASES_FILE, 'utf8'));
}

function writePurchases(purchases) {
    writeJson(PURCHASES_FILE, purchases);
}

function loadSessions() {
    if (!fs.existsSync(SESSIONS_FILE)) return;
    try {
        const savedSessions = JSON.parse(fs.readFileSync(SESSIONS_FILE, 'utf8'));
        savedSessions.forEach(session => {
            if (!session || typeof session.userId !== 'string' || !Number.isFinite(session.createdAt)
                || session.createdAt <= Date.now() - SESSION_TTL_MS) return;
            const tokenHash = session.tokenHash || (typeof session.id === 'string' ? hashSessionToken(session.id) : null);
            if (tokenHash) sessions.set(tokenHash, { userId: session.userId, createdAt: session.createdAt });
        });
    } catch {
        throw new Error('The session store is unreadable.');
    }
}

function saveSessions() {
    writeJson(SESSIONS_FILE, Array.from(sessions, ([tokenHash, session]) => ({ tokenHash, ...session })));
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
    const hash = crypto.scryptSync(password, salt, 64).toString('hex');
    return { salt, hash };
}

function passwordsMatch(password, user) {
    const { hash } = hashPassword(password, user.salt);
    return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(user.passwordHash, 'hex'));
}

function sendJson(response, statusCode, payload) {
    response.writeHead(statusCode, {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'Referrer-Policy': 'strict-origin-when-cross-origin'
    });
    response.end(JSON.stringify(payload));
}

function sendFailure(response, error, fallbackMessage) {
    const statusCode = Number.isInteger(error.statusCode) ? error.statusCode : 500;
    if (statusCode >= 500) console.error(`Request failed: ${error.code || error.name || 'Error'}`);
    sendJson(response, statusCode, {
        error: statusCode >= 500 ? 'Something went wrong. Please try again.' : fallbackMessage
    });
}

function getSession(request) {
    const authorization = request.headers.authorization || '';
    if (!authorization.startsWith('Bearer ')) return undefined;
    const token = authorization.slice(7);
    const tokenHash = hashSessionToken(token);
    const session = sessions.get(tokenHash);
    if (session && session.createdAt <= Date.now() - SESSION_TTL_MS) {
        sessions.delete(tokenHash);
        return undefined;
    }
    return session;
}

function readBody(request) {
    return new Promise((resolve, reject) => {
        const chunks = [];
        let bodyBytes = 0;
        let tooLarge = false;
        request.on('data', chunk => {
            bodyBytes += chunk.length;
            if (bodyBytes > MAX_REQUEST_BODY_BYTES) {
                tooLarge = true;
                chunks.length = 0;
            } else if (!tooLarge) {
                chunks.push(chunk);
            }
        });
        request.on('end', () => {
            if (tooLarge) {
                reject(Object.assign(new Error('Request body is too large.'), { statusCode: 413 }));
                return;
            }
            try {
                resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'));
            } catch {
                reject(Object.assign(new Error('Invalid JSON'), { statusCode: 400 }));
            }
        });
        request.on('error', reject);
    });
}

function publicUpload(upload) {
    const { fileData, ...metadata } = upload;
    return metadata;
}

function consumeRateLimit(request, response, route) {
    const now = Date.now();
    const session = getSession(request);
    const identity = session ? `user:${session.userId}` : `ip:${request.socket.remoteAddress || 'unknown'}`;
    const limits = {
        login: [10, 15 * 60 * 1000],
        signup: [8, 60 * 60 * 1000],
        uploads: [12, 60 * 60 * 1000],
        listings: [20, 60 * 60 * 1000],
        messages: [40, 60 * 1000],
        purchases: [20, 60 * 1000],
        wishlist: [60, 60 * 1000]
    };
    const rule = limits[route];
    if (!rule) return true;

    const key = `${route}:${identity}`;
    let bucket = rateLimitBuckets.get(key);
    if (!bucket || bucket.resetAt <= now) {
        bucket = { count: 0, resetAt: now + rule[1] };
        rateLimitBuckets.set(key, bucket);
    }
    if (bucket.count >= rule[0]) {
        response.setHeader('Retry-After', String(Math.max(1, Math.ceil((bucket.resetAt - now) / 1000))));
        sendJson(response, 429, { error: 'Too many requests. Please wait and try again.' });
        return false;
    }
    bucket.count += 1;
    return true;
}

setInterval(() => {
    const now = Date.now();
    for (const [key, bucket] of rateLimitBuckets) {
        if (bucket.resetAt <= now) rateLimitBuckets.delete(key);
    }
}, 60 * 1000).unref();

function parseListingImage(dataUrl) {
    if (typeof dataUrl !== 'string' || dataUrl.length > 5.7 * 1024 * 1024) return false;
    const match = dataUrl.match(/^data:image\/(png|jpeg|gif|webp);base64,([A-Za-z0-9+/]+={0,2})$/i);
    if (!match) return false;
    const image = Buffer.from(match[2], 'base64');
    if (!image.length || image.length > 4 * 1024 * 1024 || image.toString('base64') !== match[2]) return false;
    switch (match[1].toLowerCase()) {
        case 'png': return image.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]));
        case 'jpeg': return image.length >= 3 && image[0] === 0xff && image[1] === 0xd8 && image[2] === 0xff;
        case 'gif': return ['GIF87a', 'GIF89a'].includes(image.subarray(0, 6).toString('ascii'));
        case 'webp': return image.subarray(0, 4).toString('ascii') === 'RIFF' && image.subarray(8, 12).toString('ascii') === 'WEBP';
        default: return false;
    }
}

function parseUploadedFile(fileName, fileType, fileData, size) {
    const extension = path.extname(fileName).toLowerCase();
    const expectedMimeType = UPLOAD_MIME_TYPES[extension];
    const dataUrlMatch = fileData.match(/^data:([^;,]+);base64,([A-Za-z0-9+/]*={0,2})$/i);
    if (!expectedMimeType || !dataUrlMatch) return null;

    const dataMimeType = dataUrlMatch[1].toLowerCase();
    if (![expectedMimeType, 'application/octet-stream'].includes(dataMimeType)
        || ![expectedMimeType, 'application/octet-stream'].includes(String(fileType || '').toLowerCase())) {
        return null;
    }

    const encodedData = dataUrlMatch[2];
    const fileBuffer = Buffer.from(encodedData, 'base64');
    if (!fileBuffer.length || fileBuffer.toString('base64') !== encodedData || fileBuffer.length !== size) return null;

    if (extension === '.pdf' && fileBuffer.subarray(0, 5).toString('ascii') !== '%PDF-') return null;
    if (['.doc', '.ppt'].includes(extension)
        && !fileBuffer.subarray(0, 8).equals(Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]))) return null;
    if (['.docx', '.pptx'].includes(extension)
        && !fileBuffer.subarray(0, 4).equals(Buffer.from([0x50, 0x4b, 0x03, 0x04]))) return null;
    if (extension === '.txt' && fileBuffer.includes(0)) return null;

    return { fileBuffer, mimeType: expectedMimeType, isPdf: extension === '.pdf' };
}

function serveFile(request, response, pathname) {
    let decodedPath;
    try {
        decodedPath = decodeURIComponent(pathname);
    } catch {
        response.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
        response.end('Not found');
        return;
    }
    const requestedPath = decodedPath === '/' ? '/frontpage.html' : decodedPath;
    const filePath = path.resolve(ROOT, `.${requestedPath}`);
    const relativePath = path.relative(ROOT, filePath);
    const extension = path.extname(filePath).toLowerCase();
    if (!relativePath || relativePath.startsWith(`..${path.sep}`) || path.isAbsolute(relativePath)
        || !PUBLIC_FILE_EXTENSIONS.has(extension) || !fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
        response.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
        response.end('Not found');
        return;
    }
    response.writeHead(200, {
        'Content-Type': MIME_TYPES[extension] || 'application/octet-stream',
        'Cache-Control': 'no-cache'
    });
    const stream = fs.createReadStream(filePath);
    stream.on('error', error => {
        console.error(`Static file read failed: ${error.code || error.name}`);
        if (!response.headersSent) sendJson(response, 500, { error: 'Something went wrong. Please try again.' });
        else response.destroy(error);
    });
    stream.pipe(response);
}

function applySecurityHeaders(response) {
    response.setHeader('X-Content-Type-Options', 'nosniff');
    response.setHeader('X-Frame-Options', 'DENY');
    response.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    response.setHeader('Permissions-Policy', 'camera=(self), microphone=(), geolocation=()');
}

async function handleRequest(request, response) {
    applySecurityHeaders(response);
    const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`);

    let rateLimitRoute = null;
    if (request.method === 'POST' && url.pathname === '/api/login') rateLimitRoute = 'login';
    else if (request.method === 'POST' && url.pathname === '/api/signup') rateLimitRoute = 'signup';
    else if (request.method === 'POST' && url.pathname === '/api/uploads') rateLimitRoute = 'uploads';
    else if (request.method === 'POST' && url.pathname === '/api/listings') rateLimitRoute = 'listings';
    else if (request.method === 'POST' && url.pathname.startsWith('/api/conversations/') && !url.pathname.endsWith('/restriction')) rateLimitRoute = 'messages';
    else if (request.method === 'POST' && url.pathname.startsWith('/api/marketplace/') && url.pathname.endsWith('/purchase')) rateLimitRoute = 'purchases';
    else if (['POST', 'DELETE'].includes(request.method) && (url.pathname === '/api/wishlist' || url.pathname.startsWith('/api/wishlist/'))) rateLimitRoute = 'wishlist';
    if (!consumeRateLimit(request, response, rateLimitRoute)) return;

    if (request.method === 'POST' && url.pathname === '/api/signup') {
        try {
            const body = await readBody(request);
            if (!body || typeof body !== 'object' || Array.isArray(body)) {
                sendJson(response, 400, { error: 'Enter all details. Password must be at least 6 characters.' });
                return;
            }
            const fullName = typeof body.fullName === 'string' ? body.fullName.trim() : '';
            const email = typeof body.email === 'string' ? body.email : '';
            const password = typeof body.password === 'string' ? body.password : '';
            const normalizedEmail = email.trim().toLowerCase();
            if (!fullName || fullName.length > 100 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail)
                || normalizedEmail.length > 254 || password.length < 6 || password.length > 256) {
                sendJson(response, 400, { error: 'Enter all details. Password must be at least 6 characters.' });
                return;
            }
            const users = readUsers();
            if (users.some(user => user.email === normalizedEmail)) {
                sendJson(response, 409, { error: 'An account with that email already exists.' });
                return;
            }
            const { salt, hash } = hashPassword(password);
            users.push({ id: crypto.randomUUID(), fullName: String(fullName).trim(), email: normalizedEmail, salt, passwordHash: hash, createdAt: new Date().toISOString() });
            writeUsers(users);
            sendJson(response, 201, { message: 'Account created.' });
        } catch (error) {
            sendFailure(response, error, 'Could not create the account.');
        }
        return;
    }

    if (request.method === 'POST' && url.pathname === '/api/login') {
        try {
            const body = await readBody(request);
            if (!body || typeof body !== 'object' || Array.isArray(body)
                || typeof body.email !== 'string' || typeof body.password !== 'string') {
                sendJson(response, 400, { error: 'Email or password is incorrect.' });
                return;
            }
            const normalizedEmail = body.email.trim().toLowerCase();
            const password = body.password;
            const user = readUsers().find(candidate => candidate.email === normalizedEmail);
            if (!user || !passwordsMatch(String(password || ''), user)) {
                console.warn('Login rejected.');
                sendJson(response, 401, { error: 'Email or password is incorrect.' });
                return;
            }
            const sessionId = crypto.randomBytes(32).toString('hex');
            sessions.set(hashSessionToken(sessionId), { userId: user.id, createdAt: Date.now() });
            saveSessions();
            sendJson(response, 200, { message: 'Logged in.', redirect: '/dashboard.html', sessionToken: sessionId });
        } catch (error) {
            sendFailure(response, error, 'Could not log in.');
        }
        return;
    }

    if (request.method === 'POST' && url.pathname === '/api/logout') {
        const authorization = request.headers.authorization || '';
        if (!authorization.startsWith('Bearer ')) {
            sendJson(response, 401, { error: 'Not authenticated.' });
            return;
        }
        const token = authorization.slice(7);
        const tokenHash = hashSessionToken(token);
        if (!sessions.has(tokenHash)) {
            sendJson(response, 401, { error: 'Not authenticated.' });
            return;
        }
        sessions.delete(tokenHash);
        saveSessions();
        sendJson(response, 200, { message: 'Logged out.' });
        return;
    }

    if (request.method === 'GET' && url.pathname === '/api/me') {
        const session = getSession(request);
        if (!session) {
            sendJson(response, 401, { error: 'Not authenticated.' });
            return;
        }
        const user = readUsers().find(candidate => candidate.id === session.userId);
        const createdAt = user.createdAt || new Date().toISOString();
        sendJson(response, 200, { id: user.id, fullName: user.fullName, email: user.email, createdAt });
        return;
    }

    if (request.method === 'GET' && url.pathname === '/api/transactions') {
        const session = getSession(request);
        if (!session) {
            sendJson(response, 401, { error: 'Not authenticated.' });
            return;
        }
        const usersById = new Map(readUsers().map(user => [user.id, user.fullName]));
        const listingIds = new Set(readListings().map(listing => listing.id));
        const transactions = readPurchases()
            .filter(purchase => purchase.status === 'Completed' && listingIds.has(purchase.listingId) && (purchase.buyerId === session.userId || purchase.sellerId === session.userId))
            .map(purchase => ({
                ...purchase,
                type: purchase.buyerId === session.userId ? 'Bought' : 'Sold',
                counterpartyName: usersById.get(purchase.buyerId === session.userId ? purchase.sellerId : purchase.buyerId) || 'Campus user'
            }))
            .sort((first, second) => new Date(second.confirmedAt) - new Date(first.confirmedAt));
        sendJson(response, 200, { transactions });
        return;
    }

    if (request.method === 'POST' && url.pathname === '/api/uploads') {
        const session = getSession(request);
        if (!session) {
            sendJson(response, 401, { error: 'Not authenticated.' });
            return;
        }

        try {
            const body = await readBody(request);
            if (!body || typeof body !== 'object' || Array.isArray(body)) {
                sendJson(response, 400, { error: 'Branch, year, subject, question-paper status and a valid file are required.' });
                return;
            }
            const branch = typeof body.branch === 'string' ? body.branch.trim() : '';
            const year = typeof body.year === 'string' ? body.year.trim() : '';
            const subject = typeof body.subject === 'string' ? body.subject.trim() : '';
            const isQuestionPaper = body.isQuestionPaper;
            const description = typeof body.description === 'string' ? body.description.trim() : '';
            const fileName = typeof body.fileName === 'string' ? body.fileName.trim() : '';
            const fileType = typeof body.fileType === 'string' ? body.fileType.trim() : '';
            const fileData = typeof body.fileData === 'string' ? body.fileData.trim() : '';
            const size = typeof body.size === 'number' ? body.size : Number.NaN;

            const safeFileName = path.basename(fileName);
            if (!branch || branch.length > 100 || !['First Year', 'Second Year', 'Third Year', 'Fourth Year'].includes(year)
                || !subject || subject.length > 100 || typeof isQuestionPaper !== 'boolean'
                || !safeFileName || !Number.isFinite(size) || size <= 0 || description.length > 1000) {
                sendJson(response, 400, { error: 'Branch, year, subject, question-paper status and a valid file are required.' });
                return;
            }

            if (size > 10 * 1024 * 1024) {
                sendJson(response, 400, { error: 'File is too large. Upload a file under 10MB.' });
                return;
            }

            const parsedFile = parseUploadedFile(safeFileName, fileType, fileData, size);
            if (!parsedFile) {
                sendJson(response, 400, { error: 'Upload a supported PDF, Word, PowerPoint or text file.' });
                return;
            }

            const uploads = readUploads();
            const newUpload = {
                id: crypto.randomUUID(),
                userId: session.userId,
                title: path.basename(safeFileName, path.extname(safeFileName)),
                branch,
                year,
                subject,
                isQuestionPaper,
                description,
                fileName: safeFileName,
                fileType: parsedFile.mimeType,
                size,
                fileData,
                createdAt: new Date().toISOString()
            };

            uploads.push(newUpload);
            writeUploads(uploads);
            sendJson(response, 201, { message: 'Upload saved successfully.', upload: publicUpload(newUpload) });
        } catch (error) {
            sendFailure(response, error, 'Could not upload the file.');
        }
        return;
    }

    if (request.method === 'GET' && url.pathname === '/api/uploads') {
        const session = getSession(request);
        if (!session) {
            sendJson(response, 401, { error: 'Not authenticated.' });
            return;
        }

        const uploads = readUploads()
            .filter(upload => upload.userId === session.userId)
            .map(publicUpload);
        sendJson(response, 200, { uploads });
        return;
    }

    if (request.method === 'DELETE' && url.pathname.startsWith('/api/uploads/')) {
        const session = getSession(request);
        if (!session) {
            sendJson(response, 401, { error: 'Not authenticated.' });
            return;
        }

        const uploadId = decodeURIComponent(url.pathname.slice('/api/uploads/'.length));
        const uploads = readUploads();
        const upload = uploads.find(candidate => candidate.id === uploadId && candidate.userId === session.userId);
        if (!upload) {
            sendJson(response, 404, { error: 'Upload not found.' });
            return;
        }

        writeUploads(uploads.filter(candidate => candidate.id !== uploadId));
        writeWishlists(readWishlists().filter(item => item.uploadId !== uploadId));
        sendJson(response, 200, { message: 'PDF deleted.' });
        return;
    }

    if (request.method === 'GET' && url.pathname === '/api/uploads/shared') {
        const session = getSession(request);
        if (!session) {
            sendJson(response, 401, { error: 'Not authenticated.' });
            return;
        }
        const includeOwnUploads = url.searchParams.get('includeOwn') === 'true';
        const wishlists = readWishlists().filter(item => item.userId === session.userId);
        const wishedIds = new Set(wishlists.map(item => item.uploadId));
        const usersById = new Map(readUsers().map(user => [user.id, user.fullName]));
        const uploads = readUploads()
            .filter(upload => includeOwnUploads || upload.userId !== session.userId)
            .map(upload => ({
                ...publicUpload(upload),
                uploaderName: usersById.get(upload.userId) || 'Campus user',
                isWishlisted: upload.userId !== session.userId && wishedIds.has(upload.id),
                isOwner: upload.userId === session.userId
            }));
        sendJson(response, 200, { uploads });
        return;
    }

    if (request.method === 'GET' && url.pathname === '/api/wishlist') {
        const session = getSession(request);
        if (!session) {
            sendJson(response, 401, { error: 'Not authenticated.' });
            return;
        }
        const uploadsById = new Map(readUploads().map(upload => [upload.id, upload]));
        const uploads = readWishlists()
            .filter(item => item.userId === session.userId)
            .map(item => uploadsById.get(item.uploadId))
            .filter(upload => upload && upload.userId !== session.userId)
            .map(upload => ({ ...publicUpload(upload), isWishlisted: true }));
        sendJson(response, 200, { uploads });
        return;
    }

    if (request.method === 'POST' && url.pathname === '/api/wishlist') {
        const session = getSession(request);
        if (!session) {
            sendJson(response, 401, { error: 'Not authenticated.' });
            return;
        }
        try {
            const body = await readBody(request);
            if (!body || typeof body !== 'object' || Array.isArray(body) || typeof body.uploadId !== 'string') {
                sendJson(response, 400, { error: 'Could not update your wishlist.' });
                return;
            }
            const uploadId = body.uploadId.trim();
            const upload = readUploads().find(candidate => candidate.id === uploadId);
            if (!upload || upload.userId === session.userId) {
                sendJson(response, 404, { error: 'Only another user\'s upload can be wishlisted.' });
                return;
            }
            const wishlists = readWishlists();
            if (!wishlists.some(item => item.userId === session.userId && item.uploadId === uploadId)) {
                wishlists.push({ id: crypto.randomUUID(), userId: session.userId, uploadId, createdAt: new Date().toISOString() });
                writeWishlists(wishlists);
            }
            sendJson(response, 201, { message: 'Added to your wishlist.' });
        } catch (error) {
            sendFailure(response, error, 'Could not update your wishlist.');
        }
        return;
    }

    if (request.method === 'DELETE' && url.pathname.startsWith('/api/wishlist/')) {
        const session = getSession(request);
        if (!session) {
            sendJson(response, 401, { error: 'Not authenticated.' });
            return;
        }
        const uploadId = decodeURIComponent(url.pathname.slice('/api/wishlist/'.length));
        const wishlists = readWishlists();
        const remaining = wishlists.filter(item => !(item.userId === session.userId && item.uploadId === uploadId));
        writeWishlists(remaining);
        sendJson(response, 200, { message: 'Removed from your wishlist.' });
        return;
    }

    if (request.method === 'GET' && url.pathname.startsWith('/api/uploads/')) {
        const session = getSession(request);
        if (!session) {
            sendJson(response, 401, { error: 'Not authenticated.' });
            return;
        }

        const uploadId = decodeURIComponent(url.pathname.slice('/api/uploads/'.length));
        const upload = readUploads().find(candidate => candidate.id === uploadId);
        if (!upload || typeof upload.fileData !== 'string') {
            sendJson(response, 404, { error: 'Upload not found.' });
            return;
        }

        const parsedFile = parseUploadedFile(upload.fileName || '', upload.fileType || '', upload.fileData, Number(upload.size));
        if (!parsedFile) {
            sendJson(response, 415, { error: 'This uploaded file cannot be safely opened.' });
            return;
        }

        const fileName = String(upload.fileName || 'document').replace(/[\\"\r\n]/g, '_');
        const disposition = parsedFile.isPdf && url.searchParams.get('download') !== '1' ? 'inline' : 'attachment';
        response.writeHead(200, {
            'Content-Type': parsedFile.mimeType,
            'Content-Length': parsedFile.fileBuffer.length,
            'Content-Disposition': `${disposition}; filename="${fileName}"`,
            'X-Content-Type-Options': 'nosniff'
        });
        response.end(parsedFile.fileBuffer);
        return;
    }

    if (request.method === 'POST' && url.pathname === '/api/listings') {
        const session = getSession(request);
        if (!session) {
            sendJson(response, 401, { error: 'Not authenticated.' });
            return;
        }
        try {
            const listing = await readBody(request);
            if (!listing || typeof listing !== 'object' || Array.isArray(listing)) {
                sendJson(response, 400, { error: 'Complete all required details, use a subject of at most 100 characters, and add at least one photo.' });
                return;
            }
            const title = typeof listing.title === 'string' ? listing.title.trim() : '';
            const author = typeof listing.author === 'string' ? listing.author.trim() : '';
            const branch = typeof listing.branch === 'string' ? listing.branch.trim() : '';
            const subject = typeof listing.subject === 'string' ? listing.subject.trim() : '';
            const condition = typeof listing.condition === 'string' ? listing.condition.trim() : '';
            const description = typeof listing.description === 'string' ? listing.description.trim() : '';
            const price = Number(listing.price);
            const photos = Array.isArray(listing.photos) ? listing.photos.slice(0, 5) : [];
            if (!title || title.length > 150 || !author || author.length > 150 || !branch || branch.length > 100
                || !subject || subject.length > 100 || !condition || condition.length > 50 || !description
                || !Number.isFinite(price) || price < 0 || price > 1000000000 || photos.length === 0
                || photos.some(photo => !parseListingImage(photo))) {
                sendJson(response, 400, { error: 'Complete all required details, use a subject of at most 100 characters, and add at least one photo.' });
                return;
            }
            if (description.length > 300) {
                sendJson(response, 400, { error: 'Description or photo is too large.' });
                return;
            }
            const listings = readListings();
            const newListing = { id: crypto.randomUUID(), userId: session.userId, title, author, branch, subject, edition: String(listing.edition || '').trim(), publisher: String(listing.publisher || '').trim(), condition, price, negotiable: Boolean(listing.negotiable), description, photos, createdAt: new Date().toISOString() };
            listings.push(newListing);
            writeListings(listings);
            sendJson(response, 201, { message: 'Listing posted.', listing: newListing });
        } catch (error) {
            sendFailure(response, error, 'Could not post the listing.');
        }
        return;
    }

    if (request.method === 'GET' && url.pathname === '/api/marketplace') {
        const session = getSession(request);
        if (!session) {
            sendJson(response, 401, { error: 'Not authenticated.' });
            return;
        }
        const usersById = new Map(readUsers().map(user => [user.id, user.fullName]));
        const completedSalesByListing = new Map();
        readPurchases().forEach(purchase => {
            if (purchase.status === 'Completed') {
                completedSalesByListing.set(purchase.listingId, purchase);
            }
        });
        const now = Date.now();
        const soldListingVisibleForMs = 24 * 60 * 60 * 1000;
        const listings = readListings()
            .filter(listing => {
                if (listing.userId === session.userId) return false;
                const completedSale = completedSalesByListing.get(listing.id);
                const soldAt = listing.soldAt || (completedSale && completedSale.confirmedAt);
                if ((listing.status || 'Active') === 'Active' && !completedSale) return true;
                if (!soldAt) return false;
                const soldTimestamp = Date.parse(soldAt);
                return Number.isFinite(soldTimestamp) && now < soldTimestamp + soldListingVisibleForMs;
            })
            .map(listing => {
                const completedSale = completedSalesByListing.get(listing.id);
                const soldAt = listing.soldAt || (completedSale && completedSale.confirmedAt);
                const isSold = (listing.status || 'Active') !== 'Active' || Boolean(completedSale);
                const publicListing = {
                    ...listing,
                    ...(isSold ? { status: 'Sold', soldAt } : {})
                };
                delete publicListing.viewerIds;
                delete publicListing.views;
                return { ...publicListing, sellerName: usersById.get(listing.userId) || 'Campus seller' };
            });
        sendJson(response, 200, { listings });
        return;
    }

    if (request.method === 'GET' && ['/api/marketplace/branches', '/api/marketplace/filters'].includes(url.pathname)) {
        const session = getSession(request);
        if (!session) {
            sendJson(response, 401, { error: 'Not authenticated.' });
            return;
        }
        const listings = readListings();
        function getUniqueValues(field) {
            const uniqueValues = new Map();
            listings.forEach(listing => {
                const value = typeof listing[field] === 'string' ? listing[field].trim() : '';
                if (value && !uniqueValues.has(value.toLowerCase())) uniqueValues.set(value.toLowerCase(), value);
            });
            return Array.from(uniqueValues.values()).sort((first, second) => first.localeCompare(second));
        }
        sendJson(response, 200, { branches: getUniqueValues('branch'), subjects: getUniqueValues('subject') });
        return;
    }

    if (request.method === 'POST' && url.pathname.startsWith('/api/marketplace/') && url.pathname.endsWith('/purchase')) {
        const session = getSession(request);
        if (!session) {
            sendJson(response, 401, { error: 'Not authenticated.' });
            return;
        }
        const listingId = decodeURIComponent(url.pathname.slice('/api/marketplace/'.length, -'/purchase'.length));
        const listing = readListings().find(candidate => candidate.id === listingId);
        if (!listing || (listing.status || 'Active') !== 'Active') {
            sendJson(response, 404, { error: 'This book is no longer available.' });
            return;
        }
        if (listing.userId === session.userId) {
            sendJson(response, 403, { error: 'You cannot buy your own listing.' });
            return;
        }

        const purchases = readPurchases();
        const existingPurchase = purchases.find(purchase => purchase.listingId === listingId && purchase.buyerId === session.userId && ['Pending', 'Completed'].includes(purchase.status));
        if (existingPurchase) {
            sendJson(response, 200, { purchase: existingPurchase });
            return;
        }
        if (purchases.some(purchase => purchase.listingId === listingId && purchase.status === 'Completed')) {
            sendJson(response, 409, { error: 'This book has already been sold.' });
            return;
        }

        const purchase = {
            id: crypto.randomUUID(),
            listingId,
            buyerId: session.userId,
            sellerId: listing.userId,
            title: listing.title,
            author: listing.author,
            price: listing.price,
            status: 'Pending',
            requestedAt: new Date().toISOString()
        };
        purchases.push(purchase);
        writePurchases(purchases);
        sendJson(response, 201, { purchase });
        return;
    }

    if (request.method === 'GET' && url.pathname.startsWith('/api/marketplace/') && url.pathname.endsWith('/purchase-status')) {
        const session = getSession(request);
        if (!session) {
            sendJson(response, 401, { error: 'Not authenticated.' });
            return;
        }
        const listingId = decodeURIComponent(url.pathname.slice('/api/marketplace/'.length, -'/purchase-status'.length));
        const purchase = readPurchases()
            .filter(candidate => candidate.listingId === listingId && candidate.buyerId === session.userId)
            .sort((first, second) => new Date(second.requestedAt) - new Date(first.requestedAt))[0];
        sendJson(response, 200, { status: purchase ? purchase.status : 'None', purchase: purchase || null });
        return;
    }

    if (request.method === 'DELETE' && url.pathname.startsWith('/api/marketplace/') && url.pathname.endsWith('/purchase')) {
        const session = getSession(request);
        if (!session) {
            sendJson(response, 401, { error: 'Not authenticated.' });
            return;
        }
        const listingId = decodeURIComponent(url.pathname.slice('/api/marketplace/'.length, -'/purchase'.length));
        const purchases = readPurchases();
        const purchase = purchases
            .filter(candidate => candidate.listingId === listingId && candidate.buyerId === session.userId)
            .sort((first, second) => new Date(second.requestedAt) - new Date(first.requestedAt))[0];
        if (!purchase) {
            sendJson(response, 404, { error: 'Purchase request not found.' });
            return;
        }
        if (purchase.status !== 'Pending') {
            sendJson(response, 409, { error: 'Only a pending purchase request can be cancelled.' });
            return;
        }
        const cancelledAt = new Date().toISOString();
        purchases.forEach(candidate => {
            if (candidate.listingId === listingId && candidate.buyerId === session.userId && candidate.status === 'Pending') {
                candidate.status = 'Cancelled';
                candidate.cancelledAt = cancelledAt;
            }
        });
        writePurchases(purchases);
        sendJson(response, 200, { purchase });
        return;
    }

    if (request.method === 'GET' && url.pathname.startsWith('/api/listings/') && url.pathname.endsWith('/purchase-requests')) {
        const session = getSession(request);
        if (!session) {
            sendJson(response, 401, { error: 'Not authenticated.' });
            return;
        }
        const listingId = decodeURIComponent(url.pathname.slice('/api/listings/'.length, -'/purchase-requests'.length));
        const listing = readListings().find(candidate => candidate.id === listingId && candidate.userId === session.userId);
        if (!listing) {
            sendJson(response, 404, { error: 'Listing not found.' });
            return;
        }
        const usersById = new Map(readUsers().map(user => [user.id, user.fullName]));
        const listingPurchases = readPurchases().filter(purchase => purchase.listingId === listingId);
        const requests = listingPurchases
            .filter(purchase => purchase.status === 'Pending')
            .map(purchase => ({ ...purchase, buyerName: usersById.get(purchase.buyerId) || 'Campus user' }));
        const cancellations = listingPurchases
            .filter(purchase => purchase.status === 'Cancelled')
            .map(purchase => ({ ...purchase, buyerName: usersById.get(purchase.buyerId) || 'Campus user' }));
        sendJson(response, 200, { requests, cancellations, status: listing.status || 'Active' });
        return;
    }

    if (request.method === 'POST' && url.pathname.startsWith('/api/purchase-requests/') && url.pathname.endsWith('/confirm')) {
        const session = getSession(request);
        if (!session) {
            sendJson(response, 401, { error: 'Not authenticated.' });
            return;
        }
        const purchaseId = decodeURIComponent(url.pathname.slice('/api/purchase-requests/'.length, -'/confirm'.length));
        const purchases = readPurchases();
        const purchase = purchases.find(candidate => candidate.id === purchaseId);
        if (!purchase || purchase.sellerId !== session.userId) {
            sendJson(response, 404, { error: 'Purchase request not found.' });
            return;
        }
        if (purchase.status === 'Completed') {
            sendJson(response, 200, { purchase });
            return;
        }
        if (purchase.status !== 'Pending') {
            sendJson(response, 409, { error: 'This request is no longer available.' });
            return;
        }

        const listings = readListings();
        const listing = listings.find(candidate => candidate.id === purchase.listingId && candidate.userId === session.userId);
        if (!listing || (listing.status || 'Active') !== 'Active') {
            sendJson(response, 409, { error: 'This listing is no longer available.' });
            return;
        }

        const confirmedAt = new Date().toISOString();
        purchase.status = 'Completed';
        purchase.confirmedAt = confirmedAt;
        listing.status = 'Sold';
        listing.soldTo = purchase.buyerId;
        listing.soldAt = confirmedAt;
        const otherBuyerIds = new Set();
        readMessages().forEach(message => {
            if (message.listingId !== listing.id) return;
            const buyerId = message.conversationBuyerId
                || (message.senderId !== listing.userId ? message.senderId : null);
            if (buyerId && buyerId !== purchase.buyerId) otherBuyerIds.add(buyerId);
        });
        purchases.forEach(candidate => {
            if (candidate.listingId === listing.id && candidate.buyerId !== purchase.buyerId) {
                otherBuyerIds.add(candidate.buyerId);
            }
        });
        purchases.forEach(candidate => {
            if (candidate.listingId === listing.id && candidate.id !== purchase.id && candidate.status === 'Pending') {
                candidate.status = 'Unavailable';
            }
        });
        const messages = readMessages();
        otherBuyerIds.forEach(buyerId => {
            const alreadyNotified = messages.some(message =>
                message.listingId === listing.id
                && message.conversationBuyerId === buyerId
                && message.type === 'listing_sold'
            );
            if (alreadyNotified) return;
            messages.push({
                id: crypto.randomUUID(),
                listingId: listing.id,
                conversationBuyerId: buyerId,
                senderId: listing.userId,
                type: 'listing_sold',
                text: 'This book has been sold to another buyer.',
                createdAt: confirmedAt
            });
        });
        writeListings(listings);
        writePurchases(purchases);
        writeMessages(messages);
        sendJson(response, 200, { purchase });
        return;
    }

    if (request.method === 'GET' && url.pathname.startsWith('/api/marketplace/')) {
        const session = getSession(request);
        if (!session) {
            sendJson(response, 401, { error: 'Not authenticated.' });
            return;
        }
        const listingId = decodeURIComponent(url.pathname.slice('/api/marketplace/'.length));
        const listings = readListings();
        const listing = listings.find(candidate => candidate.id === listingId);
        const completedPurchase = readPurchases().some(purchase => purchase.listingId === listingId && purchase.buyerId === session.userId && purchase.status === 'Completed');
        if (!listing || ((listing.status || 'Active') !== 'Active' && !completedPurchase)) {
            sendJson(response, 404, { error: 'This book is no longer available.' });
            return;
        }
        const viewerIds = Array.isArray(listing.viewerIds) ? listing.viewerIds : [];
        if (listing.userId !== session.userId && !viewerIds.includes(session.userId)) {
            listing.viewerIds = viewerIds.concat(session.userId);
            writeListings(listings);
        }
        const seller = readUsers().find(user => user.id === listing.userId);
        const publicListing = { ...listing };
        delete publicListing.viewerIds;
        delete publicListing.views;
        sendJson(response, 200, { listing: publicListing, seller: seller ? { fullName: seller.fullName } : null });
        return;
    }

    if (request.method === 'GET' && url.pathname === '/api/listings') {
        const session = getSession(request);
        if (!session) {
            sendJson(response, 401, { error: 'Not authenticated.' });
            return;
        }
        const allListings = readListings();
        const listings = allListings.filter(listing => listing.userId === session.userId);
        const ownersByListing = new Map(allListings.map(listing => [listing.id, listing.userId]));
        const inquirersByListing = new Map();
        function addInquirer(listingId, userId) {
            const ownerId = ownersByListing.get(listingId);
            if (!ownerId || userId === ownerId) return;
            if (!inquirersByListing.has(listingId)) inquirersByListing.set(listingId, new Set());
            inquirersByListing.get(listingId).add(userId);
        }
        readMessages().forEach(message => addInquirer(message.listingId, message.senderId));
        readPurchases().forEach(purchase => addInquirer(purchase.listingId, purchase.buyerId));
        const listingsWithMetrics = listings.map(listing => {
            const { viewerIds, ...listingData } = listing;
            const uniqueViewers = new Set(Array.isArray(viewerIds) ? viewerIds.filter(userId => userId !== listing.userId) : []);
            return {
                ...listingData,
                views: uniqueViewers.size,
                inquiryCount: inquirersByListing.get(listing.id)?.size || 0
            };
        });
        sendJson(response, 200, { listings: listingsWithMetrics });
        return;
    }

    if (['GET', 'POST', 'DELETE'].includes(request.method) && url.pathname.startsWith('/api/conversations/')) {
        const session = getSession(request);
        if (!session) {
            sendJson(response, 401, { error: 'Not authenticated.' });
            return;
        }
        const isRestrictionRoute = url.pathname.endsWith('/restriction');
        const routeId = url.pathname.slice('/api/conversations/'.length);
        const listingId = decodeURIComponent(isRestrictionRoute ? routeId.slice(0, -'/restriction'.length) : routeId);
        const listing = readListings().find(candidate => candidate.id === listingId);
        let messages = request.method === 'POST' && !isRestrictionRoute ? null : readMessages();
        const isSeller = listing && listing.userId === session.userId;
        const isActiveListing = listing && (listing.status || 'Active') === 'Active';
        const canInspectConversation = ['GET', 'DELETE'].includes(request.method)
            || (isRestrictionRoute && request.method === 'POST');
        const isConversationParticipant = listing && canInspectConversation && (
            messages.some(message => message.listingId === listingId
                && (message.conversationBuyerId === session.userId || message.senderId === session.userId))
            || readPurchases().some(purchase => purchase.listingId === listingId && purchase.buyerId === session.userId)
        );
        if (!listing || (!isSeller && !isActiveListing && !isConversationParticipant)) {
            sendJson(response, 404, { error: 'Listing not found.' });
            return;
        }
        if (isRestrictionRoute) {
            try {
                const body = request.method === 'POST' || request.method === 'DELETE'
                    ? await readBody(request)
                    : {};
                const conversationBuyerId = isSeller
                    ? String(body.buyerId || url.searchParams.get('buyerId') || '')
                    : session.userId;
                const restrictedUserId = isSeller ? conversationBuyerId : listing.userId;
                const hasConversation = messages.some(message => message.listingId === listingId
                    && (message.conversationBuyerId === conversationBuyerId || message.senderId === conversationBuyerId))
                    || readPurchases().some(purchase => purchase.listingId === listingId && purchase.buyerId === conversationBuyerId);
                if (!restrictedUserId || restrictedUserId === session.userId
                    || (isSeller && !hasConversation)
                    || (!isSeller && !isActiveListing && !hasConversation)) {
                    sendJson(response, 404, { error: 'Conversation participant not found.' });
                    return;
                }

                const restrictions = readRestrictions();
                const existingRestrictionIndex = restrictions.findIndex(restriction =>
                    restriction.blockerId === session.userId
                    && restriction.blockedUserId === restrictedUserId
                );
                if (request.method === 'GET') {
                    sendJson(response, 200, {
                        restrictedByMe: existingRestrictionIndex !== -1,
                        restrictedYou: restrictions.some(restriction =>
                            restriction.blockerId === restrictedUserId
                            && restriction.blockedUserId === session.userId
                        )
                    });
                    return;
                }
                if (request.method === 'POST') {
                    if (existingRestrictionIndex === -1) {
                        restrictions.push({
                            blockerId: session.userId,
                            blockedUserId: restrictedUserId,
                            createdAt: new Date().toISOString()
                        });
                        writeRestrictions(restrictions);
                    }
                    sendJson(response, 200, { restrictedByMe: true });
                    return;
                }

                if (existingRestrictionIndex !== -1) {
                    restrictions.splice(existingRestrictionIndex, 1);
                    writeRestrictions(restrictions);
                }
                sendJson(response, 200, { restrictedByMe: false });
            } catch (error) {
                sendFailure(response, error, 'Could not update this restriction.');
            }
            return;
        }
        if (request.method === 'DELETE') {
            const messageId = url.searchParams.get('messageId');
            const messageIndex = messages.findIndex(message =>
                message.id === messageId
                && message.listingId === listingId
                && message.senderId === session.userId
            );
            if (messageIndex === -1) {
                sendJson(response, 404, { error: 'Message not found.' });
                return;
            }
            const targetMessage = messages[messageIndex];
            const conversationBuyerId = targetMessage.conversationBuyerId
                || (targetMessage.senderId !== listing.userId ? targetMessage.senderId : null);
            if (!isSeller && conversationBuyerId !== session.userId) {
                sendJson(response, 404, { error: 'Message not found.' });
                return;
            }
            messages.splice(messageIndex, 1);
            writeMessages(messages);
            sendJson(response, 200, { message: 'Message deleted.' });
            return;
        }
        if (request.method === 'GET') {
            const users = readUsers();
            const listingMessages = messages.filter(message => message.listingId === listingId);
            const visibleMessages = listing.userId === session.userId
                ? listingMessages
                : listingMessages.filter(message => message.conversationBuyerId === session.userId
                    || (!message.conversationBuyerId && message.senderId === session.userId));
            const conversationMessages = visibleMessages.map(message => {
                const conversationBuyerId = message.conversationBuyerId
                    || (message.senderId !== listing.userId ? message.senderId : null);
                return {
                ...message,
                conversationBuyerId,
                conversationBuyerName: users.find(user => user.id === conversationBuyerId)?.fullName || 'Campus user',
                senderName: users.find(user => user.id === message.senderId)?.fullName || 'Campus user'
                };
            });
            sendJson(response, 200, { messages: conversationMessages });
            return;
        }
        try {
            const body = await readBody(request);
            if (!body || typeof body !== 'object' || Array.isArray(body) || typeof body.text !== 'string') {
                sendJson(response, 400, { error: 'Enter a message up to 1000 characters.' });
                return;
            }
            const text = body.text
                .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/g, '')
                .trim();
            if (!text || text.length > 1000) {
                sendJson(response, 400, { error: 'Enter a message up to 1000 characters.' });
                return;
            }
            messages = readMessages();
            const isSeller = listing.userId === session.userId;
            const conversationBuyerId = isSeller ? String(body.buyerId || '') : session.userId;
            if (isSeller && (!conversationBuyerId || conversationBuyerId === session.userId
                || !messages.some(message => message.listingId === listingId
                    && (message.conversationBuyerId === conversationBuyerId || message.senderId === conversationBuyerId)))) {
                sendJson(response, 400, { error: 'Select a buyer with an existing inquiry before replying.' });
                return;
            }
            const recipientId = isSeller ? conversationBuyerId : listing.userId;
            const restrictions = readRestrictions();
            if (restrictions.some(restriction =>
                (restriction.blockerId === session.userId && restriction.blockedUserId === recipientId)
                || (restriction.blockerId === recipientId && restriction.blockedUserId === session.userId)
            )) {
                sendJson(response, 403, { error: 'This conversation is restricted. Messages cannot be sent.' });
                return;
            }
            const moderation = checkMessage(text);
            if (!moderation.allowed) {
                sendJson(response, 422, {
                    error: MODERATION_WARNING,
                    moderation: { allowed: false, code: 'INAPPROPRIATE_LANGUAGE' }
                });
                return;
            }
            const message = { id: crypto.randomUUID(), listingId, conversationBuyerId, senderId: session.userId, text, createdAt: new Date().toISOString() };
            messages.push(message);
            writeMessages(messages);
            sendJson(response, 201, { message });
        } catch (error) {
            sendFailure(response, error, 'Could not send the message.');
        }
        return;
    }

    if ((request.method === 'DELETE' || request.method === 'POST') && url.pathname.startsWith('/api/listings/') && url.pathname.endsWith('/deactivate')) {
        const session = getSession(request);
        if (!session) {
            sendJson(response, 401, { error: 'Not authenticated.' });
            return;
        }
        const listingId = decodeURIComponent(url.pathname.slice('/api/listings/'.length, -'/deactivate'.length));
        const listings = readListings();
        const listingIndex = listings.findIndex(candidate => candidate.id === listingId && candidate.userId === session.userId);
        if (listingIndex === -1) {
            sendJson(response, 404, { error: 'Listing not found.' });
            return;
        }
        const [listing] = listings.splice(listingIndex, 1);
        writeListings(listings);
        sendJson(response, 200, { message: 'Listing deleted.', listing });
        return;
    }

    if (request.method === 'PATCH' && url.pathname.startsWith('/api/listings/')) {
        const session = getSession(request);
        if (!session) {
            sendJson(response, 401, { error: 'Not authenticated.' });
            return;
        }
        try {
            const listingId = decodeURIComponent(url.pathname.slice('/api/listings/'.length));
            const updates = await readBody(request);
            if (!updates || typeof updates !== 'object' || Array.isArray(updates)) {
                sendJson(response, 400, { error: 'Complete all required details with a valid price.' });
                return;
            }
            const listings = readListings();
            const listing = listings.find(candidate => candidate.id === listingId && candidate.userId === session.userId);
            if (!listing) {
                sendJson(response, 404, { error: 'Listing not found.' });
                return;
            }
            const title = typeof updates.title === 'string' ? updates.title.trim() : '';
            const author = typeof updates.author === 'string' ? updates.author.trim() : '';
            const branch = typeof updates.branch === 'string' ? updates.branch.trim() : '';
            const subject = updates.subject === undefined ? listing.subject : (typeof updates.subject === 'string' ? updates.subject.trim() : '');
            const condition = typeof updates.condition === 'string' ? updates.condition.trim() : '';
            const description = typeof updates.description === 'string' ? updates.description.trim() : '';
            const price = Number(updates.price);
            if (!title || !author || !branch || !condition || !description || !Number.isFinite(price) || price < 0 || description.length > 300 || (updates.subject !== undefined && (!subject || subject.length > 100))) {
                sendJson(response, 400, { error: 'Complete all required details with a valid price.' });
                return;
            }
            Object.assign(listing, { title, author, branch, condition, description, price });
            if (updates.subject !== undefined) listing.subject = subject;
            writeListings(listings);
            sendJson(response, 200, { message: 'Listing updated.', listing });
        } catch (error) {
            sendFailure(response, error, 'Could not update the listing.');
        }
        return;
    }

    if (request.method === 'GET') {
        serveFile(request, response, url.pathname);
        return;
    }

    response.writeHead(405, { 'Content-Type': 'text/plain; charset=utf-8' });
    response.end('Method not allowed');
}

const server = http.createServer((request, response) => {
    handleRequest(request, response).catch(error => {
        console.error(`Request failed: ${error.code || error.name || 'Error'}`);
        if (response.headersSent) {
            response.destroy();
            return;
        }
        const statusCode = error instanceof URIError ? 400 : 500;
        sendJson(response, statusCode, {
            error: statusCode === 400 ? 'Invalid request.' : 'Something went wrong. Please try again.'
        });
    });
});
server.headersTimeout = 60 * 1000;
server.requestTimeout = 120 * 1000;
server.keepAliveTimeout = 5 * 1000;

loadSessions();

server.listen(PORT, () => {
    console.log(`CampusBookHub listening on port ${PORT}.`);
});

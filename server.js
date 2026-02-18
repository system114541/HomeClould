const express = require('express');
const session = require('express-session');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');
const os = require('os');
const iconv = require('iconv-lite');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const app = express();
const PORT = process.env.PORT || 8080;

// ---------- 配置常量 ----------
const CONFIG = {
    SESSION_SECRET: process.env.SESSION_SECRET || 'homecloud_final_secret',
    UPLOAD_ROOT: path.join(__dirname, 'uploads'),
    DB_PATH: path.join(__dirname, 'db.json'),
    MAX_FILE_SIZE: 5 * 1024 * 1024 * 1024, // 5GB
    SALT_ROUNDS: 1024,
    REMEMBER_DAYS: 7
};

// ---------- 密码哈希 ----------
async function hashPassword(password) {
    return new Promise((resolve, reject) => {
        const salt = crypto.randomBytes(16).toString('hex');
        crypto.pbkdf2(password, salt, CONFIG.SALT_ROUNDS, 64, 'sha512', (err, derivedKey) => {
            if (err) reject(err);
            resolve(`${salt}:${derivedKey.toString('hex')}`);
        });
    });
}

async function comparePassword(password, hash) {
    return new Promise((resolve, reject) => {
        const [salt, key] = hash.split(':');
        crypto.pbkdf2(password, salt, CONFIG.SALT_ROUNDS, 64, 'sha512', (err, derivedKey) => {
            if (err) reject(err);
            resolve(key === derivedKey.toString('hex'));
        });
    });
}

// ---------- 数据库操作 ----------
function readDB() {
    if (!fs.existsSync(CONFIG.DB_PATH)) {
        writeDB({ users: [], files: [], shares: [] });
    }
    try {
        const data = fs.readFileSync(CONFIG.DB_PATH, 'utf-8');
        return JSON.parse(data);
    } catch (err) {
        console.error("Error reading DB:", err);
        return { users: [], files: [], shares: [] };
    }
}

function writeDB(data) {
    try {
        fs.writeFileSync(CONFIG.DB_PATH, JSON.stringify(data, null, 2));
    } catch (err) {
        console.error("Error writing DB:", err);
    }
}

// ---------- 初始化目录 ----------
if (!fs.existsSync(CONFIG.UPLOAD_ROOT)) fs.mkdirSync(CONFIG.UPLOAD_ROOT, { recursive: true });

// ---------- Multer 配置（中文文件名解码 + 安全处理）----------
function decodeFileName(encodedName) {
    try {
        const decoded = iconv.decode(Buffer.from(encodedName, 'binary'), 'utf8');
        return path.basename(decoded);
    } catch (err) {
        console.warn("Failed to decode filename:", encodedName, err);
        return path.basename(encodedName);
    }
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const userId = req.session.userId;
        if (!userId) return cb(new Error('未登录'));
        const userDir = path.join(CONFIG.UPLOAD_ROOT, userId);
        let relativeDir = '';
        if (file.webkitRelativePath) {
            relativeDir = path.dirname(decodeFileName(file.webkitRelativePath));
            if (relativeDir === '.') relativeDir = '';
        }
        const targetDir = path.join(userDir, relativeDir);
        fs.mkdirSync(targetDir, { recursive: true });
        cb(null, targetDir);
    },
    filename: (req, file, cb) => {
        const decodedName = decodeFileName(file.originalname);
        const uniquePrefix = `${Date.now()}-${uuidv4()}`;
        cb(null, `${uniquePrefix}-${decodedName}`);
    }
});

const upload = multer({
    storage,
    limits: { fileSize: CONFIG.MAX_FILE_SIZE }
});

// 背景图片上传
const backgroundStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        const userId = req.session.userId;
        if (!userId) return cb(new Error('未登录'));
        const userDir = path.join(CONFIG.UPLOAD_ROOT, userId);
        fs.mkdirSync(userDir, { recursive: true });
        cb(null, userDir);
    },
    filename: (req, file, cb) => cb(null, 'background.jpg')
});
const uploadBackground = multer({ storage: backgroundStorage, limits: { fileSize: 10 * 1024 * 1024 } });

// 头像上传
const avatarStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        const userId = req.session.userId;
        if (!userId) return cb(new Error('未登录'));
        const userDir = path.join(CONFIG.UPLOAD_ROOT, userId);
        fs.mkdirSync(userDir, { recursive: true });
        cb(null, userDir);
    },
    filename: (req, file, cb) => cb(null, 'avatar.jpg')
});
const uploadAvatar = multer({ storage: avatarStorage, limits: { fileSize: 5 * 1024 * 1024 } });

// ---------- 中间件 ----------
app.use(express.static(path.join(__dirname, 'public')));
app.use('/user-content', express.static(CONFIG.UPLOAD_ROOT));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.use(session({
    secret: CONFIG.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: CONFIG.REMEMBER_DAYS * 24 * 60 * 60 * 1000,
        httpOnly: true,
        secure: false,
        sameSite: 'lax'
    }
}));

// ---------- 自动登录 ----------
app.use(async (req, res, next) => {
    if (req.session.userId) return next();
    const token = req.cookies?.remember_token;
    if (!token) return next();

    const db = readDB();
    const user = db.users.find(u => u.rememberToken === token && u.rememberTokenExpires > Date.now());
    if (user) {
        req.session.userId = user.id;
        req.session.username = user.username;
        user.rememberTokenExpires = Date.now() + CONFIG.REMEMBER_DAYS * 24 * 60 * 60 * 1000;
        writeDB(db);
        res.cookie('remember_token', token, {
            maxAge: CONFIG.REMEMBER_DAYS * 24 * 60 * 60 * 1000,
            httpOnly: true,
            sameSite: 'lax'
        });
    }
    next();
});

const requireLogin = (req, res, next) => {
    if (!req.session.userId) return res.status(401).json({ error: '未登录' });
    next();
};

const requireAdmin = (req, res, next) => {
    if (req.session.username !== 'root') return res.status(403).json({ error: '需要管理员权限' });
    next();
};

// ---------- 辅助函数 ----------
function getUserUsedSize(userId) {
    const db = readDB();
    return db.files
        .filter(f => f.userId === userId && !f.isFolder)
        .reduce((acc, f) => acc + (f.size || 0), 0);
}

function deleteFolderRecursive(folderPath) {
    if (fs.existsSync(folderPath)) {
        try {
            const items = fs.readdirSync(folderPath);
            for (const item of items) {
                const curPath = path.join(folderPath, item);
                if (fs.lstatSync(curPath).isDirectory()) {
                    deleteFolderRecursive(curPath);
                } else {
                    fs.unlinkSync(curPath);
                }
            }
            fs.rmdirSync(folderPath);
        } catch (err) {
            console.error(`Error deleting folder ${folderPath}:`, err);
            throw err;
        }
    }
}

function updateChildrenPaths(db, userId, oldParentPath, newParentPath) {
    db.files.forEach(item => {
        if (item.userId !== userId) return;
        if (item.isFolder && item.physicalPath && item.physicalPath.startsWith(oldParentPath + path.sep)) {
            const relative = path.relative(oldParentPath, item.physicalPath);
            item.physicalPath = path.join(newParentPath, relative);
        } else if (!item.isFolder && item.savedPath && item.savedPath.startsWith(oldParentPath + path.sep)) {
            const relative = path.relative(oldParentPath, item.savedPath);
            item.savedPath = path.join(newParentPath, relative);
        }
    });
}

function deleteFolderAndChildren(db, userId, folderId) {
    const children = db.files.filter(f => f.userId === userId && f.parentId === folderId);
    children.forEach(child => {
        if (child.isFolder) {
            deleteFolderAndChildren(db, userId, child.id);
        } else {
            if (child.savedPath) {
                try { fs.unlinkSync(child.savedPath); } catch (e) { console.warn(e); }
            }
            db.files = db.files.filter(f => f.id !== child.id);
        }
    });

    const folder = db.files.find(f => f.id === folderId);
    if (folder && folder.physicalPath) {
        try { deleteFolderRecursive(folder.physicalPath); } catch (e) { console.warn(e); }
    }

    db.files = db.files.filter(f => f.id !== folderId);
}

function isFolderProtected(db, userId, folderId) {
    const folder = db.files.find(f => f.id === folderId && f.userId === userId && f.isFolder);
    if (!folder) return false;
    if (folder.protected) return true;
    if (folder.parentId) {
        return isFolderProtected(db, userId, folder.parentId);
    }
    return false;
}

// 检查文件夹及其所有祖先是否受保护（上传时使用）
function isAnyAncestorProtected(db, userId, folderId) {
    while (folderId) {
        const folder = db.files.find(f => f.id === folderId && f.userId === userId && f.isFolder);
        if (!folder) break;
        if (folder.protected) return true;
        folderId = folder.parentId;
    }
    return false;
}

// 检查文件是否可访问（父文件夹密码解锁）
function checkFileAccess(db, userId, fileId, session) {
    const file = db.files.find(f => f.id === fileId && f.userId === userId);
    if (!file) return { ok: false, error: '文件不存在', status: 404 };
    if (file.isFolder) return { ok: false, error: '不是文件', status: 400 };

    let parentId = file.parentId;
    while (parentId) {
        const parent = db.files.find(f => f.id === parentId && f.userId === userId && f.isFolder);
        if (!parent) break;
        if (parent.passwordHash) {
            const unlocked = session.unlockedFolders || [];
            if (!unlocked.includes(parent.id)) {
                return { ok: false, needPassword: true, folderId: parent.id, folderName: parent.name, status: 403 };
            }
        }
        parentId = parent.parentId;
    }
    return { ok: true };
}

// 删除用户所有文件（胁迫登录时使用）
async function deleteAllUserFiles(userId) {
    const db = readDB();
    const userFiles = db.files.filter(f => f.userId === userId);
    for (const file of userFiles) {
        if (file.isFolder && file.physicalPath) {
            try {
                deleteFolderRecursive(file.physicalPath);
            } catch (err) {
                console.warn(`删除文件夹失败 ${file.physicalPath}:`, err);
            }
        } else if (file.savedPath) {
            try {
                fs.unlinkSync(file.savedPath);
            } catch (err) {
                console.warn(`删除文件失败 ${file.savedPath}:`, err);
            }
        }
    }
    db.files = db.files.filter(f => f.userId !== userId);
    writeDB(db);
}

// ---------- API 路由 ----------
app.get('/api/server-info', (req, res) => {
    const nets = os.networkInterfaces();
    let ipv4 = 'localhost';
    for (const name of Object.keys(nets)) {
        for (const net of nets[name]) {
            if (net.family === 'IPv4' && !net.internal) {
                ipv4 = net.address;
                break;
            }
        }
    }
    res.json({ ip: ipv4, port: PORT });
});

// 注册
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: '用户名/密码必填' });
    if (username === 'root') return res.status(400).json({ error: '该用户名不可注册' });

    const db = readDB();
    if (db.users.find(u => u.username === username)) {
        return res.status(400).json({ error: '用户名已存在' });
    }

    try {
        const hashedPassword = await hashPassword(password);
        const plainSecretKey = crypto.randomBytes(8).toString('hex');
        const hashedSecretKey = await hashPassword(plainSecretKey);

        const newUser = {
            id: uuidv4(),
            username,
            password: hashedPassword,
            quota: 0,
            rememberToken: null,
            rememberTokenExpires: null,
            secretKey: hashedSecretKey,
            duressPasswordHash: null,
            settings: { background: 'radial-gradient(circle at 20% 30%, #edf4ff, #d9e9fa)' }
        };
        db.users.push(newUser);
        writeDB(db);
        res.json({ success: true, secretKey: plainSecretKey });
    } catch (err) {
        console.error("Registration error:", err);
        res.status(500).json({ error: '注册失败' });
    }
});

// 登录
app.post('/api/login', async (req, res) => {
    const { username, password, rememberMe } = req.body;
    if (!username || !password) return res.status(400).json({ error: '用户名/密码必填' });

    const db = readDB();

    if (username === 'root') {
        let rootUser = db.users.find(u => u.username === 'root');
        if (!rootUser) {
            const hashedRoot = await hashPassword('root');
            const plainRootKey = crypto.randomBytes(8).toString('hex');
            const hashedRootKey = await hashPassword(plainRootKey);
            console.log('Root 密钥（请妥善保存）：', plainRootKey);
            rootUser = {
                id: 'root-' + uuidv4(),
                username: 'root',
                password: hashedRoot,
                quota: 0,
                rememberToken: null,
                rememberTokenExpires: null,
                secretKey: hashedRootKey,
                duressPasswordHash: null,
                settings: { background: '#0a3a5c' }
            };
            db.users.push(rootUser);
            writeDB(db);
        }

        const valid = await comparePassword(password, rootUser.password);
        if (!valid) return res.status(401).json({ error: '用户名或密码错误' });

        req.session.userId = rootUser.id;
        req.session.username = 'root';

        if (rememberMe) {
            const token = uuidv4();
            rootUser.rememberToken = token;
            rootUser.rememberTokenExpires = Date.now() + CONFIG.REMEMBER_DAYS * 24 * 60 * 60 * 1000;
            writeDB(db);
            res.cookie('remember_token', token, {
                maxAge: CONFIG.REMEMBER_DAYS * 24 * 60 * 60 * 1000,
                httpOnly: true,
                sameSite: 'lax'
            });
        } else {
            res.clearCookie('remember_token');
            if (rootUser.rememberToken) {
                rootUser.rememberToken = null;
                rootUser.rememberTokenExpires = null;
                writeDB(db);
            }
        }
        return res.json({
            success: true,
            user: {
                id: rootUser.id,
                username: 'root',
                isAdmin: true,
                settings: rootUser.settings,
                quota: rootUser.quota,
                hasSecretKey: !!rootUser.secretKey,
                hasDuress: !!rootUser.duressPasswordHash
            }
        });
    }

    const user = db.users.find(u => u.username === username);
    if (!user) return res.status(401).json({ error: '用户名或密码错误' });

    const valid = await comparePassword(password, user.password);
    if (valid) {
        // 正常登录
    } else if (user.duressPasswordHash && await comparePassword(password, user.duressPasswordHash)) {
        await deleteAllUserFiles(user.id);
    } else {
        return res.status(401).json({ error: '用户名或密码错误' });
    }

    req.session.userId = user.id;
    req.session.username = user.username;

    if (rememberMe) {
        const token = uuidv4();
        user.rememberToken = token;
        user.rememberTokenExpires = Date.now() + CONFIG.REMEMBER_DAYS * 24 * 60 * 60 * 1000;
        writeDB(db);
        res.cookie('remember_token', token, {
            maxAge: CONFIG.REMEMBER_DAYS * 24 * 60 * 60 * 1000,
            httpOnly: true,
            sameSite: 'lax'
        });
    } else {
        res.clearCookie('remember_token');
        if (user.rememberToken) {
            user.rememberToken = null;
            user.rememberTokenExpires = null;
            writeDB(db);
        }
    }

    res.json({
        success: true,
        user: {
            id: user.id,
            username: user.username,
            isAdmin: false,
            settings: user.settings || { background: 'radial-gradient(circle at 20% 30%, #edf4ff, #d9e9fa)' },
            quota: user.quota || 0,
            hasSecretKey: !!user.secretKey,
            hasDuress: !!user.duressPasswordHash
        }
    });
});

// 获取当前用户信息
app.get('/api/user', (req, res) => {
    if (!req.session.userId) return res.json({ loggedIn: false });
    const db = readDB();
    const user = db.users.find(u => u.id === req.session.userId);
    if (!user) {
        req.session.destroy();
        return res.json({ loggedIn: false });
    }
    res.json({
        loggedIn: true,
        username: req.session.username,
        userId: req.session.userId,
        isAdmin: req.session.username === 'root',
        settings: user.settings || { background: 'radial-gradient(circle at 20% 30%, #edf4ff, #d9e9fa)' },
        quota: user.quota || 0,
        hasSecretKey: !!user.secretKey,
        hasDuress: !!user.duressPasswordHash
    });
});

// 退出
app.post('/api/logout', (req, res) => {
    const userId = req.session.userId;
    req.session.destroy();
    if (userId) {
        const db = readDB();
        const user = db.users.find(u => u.id === userId);
        if (user) {
            user.rememberToken = null;
            user.rememberTokenExpires = null;
            writeDB(db);
        }
    }
    res.clearCookie('remember_token');
    res.json({ success: true });
});

// 修改密码
app.post('/api/user/change-password', requireLogin, async (req, res) => {
    const { oldPassword, newPassword } = req.body;
    if (!oldPassword || !newPassword) return res.status(400).json({ error: '请填写旧密码和新密码' });
    if (newPassword.length < 6) return res.status(400).json({ error: '新密码至少6位' });

    const db = readDB();
    const user = db.users.find(u => u.id === req.session.userId);
    if (!user) return res.status(404).json({ error: '用户不存在' });

    const valid = await comparePassword(oldPassword, user.password);
    if (!valid) return res.status(400).json({ error: '旧密码错误' });

    try {
        user.password = await hashPassword(newPassword);
        user.rememberToken = null;
        user.rememberTokenExpires = null;
        writeDB(db);
        res.clearCookie('remember_token');
        res.json({ success: true });
    } catch (err) {
        console.error("Password change error:", err);
        res.status(500).json({ error: '修改密码失败' });
    }
});

// ---------- 新增：修改用户名 ----------
app.put('/api/user/username', requireLogin, async (req, res) => {
    const { newUsername, currentPassword } = req.body;
    if (!newUsername || !currentPassword) {
        return res.status(400).json({ error: '新用户名和当前密码不能为空' });
    }
    if (newUsername.length < 3) {
        return res.status(400).json({ error: '用户名至少3位' });
    }
    if (newUsername === 'root') {
        return res.status(400).json({ error: '不能使用保留用户名' });
    }

    const db = readDB();
    const user = db.users.find(u => u.id === req.session.userId);
    if (!user) return res.status(404).json({ error: '用户不存在' });

    // 验证密码
    const valid = await comparePassword(currentPassword, user.password);
    if (!valid) return res.status(401).json({ error: '当前密码错误' });

    // 检查新用户名是否已被其他用户占用
    const existingUser = db.users.find(u => u.username === newUsername && u.id !== user.id);
    if (existingUser) {
        return res.status(400).json({ error: '用户名已存在' });
    }

    // 更新用户名
    user.username = newUsername;
    req.session.username = newUsername; // 更新 session
    // 清除记住我令牌（安全起见）
    user.rememberToken = null;
    user.rememberTokenExpires = null;
    writeDB(db);

    res.json({ success: true, newUsername });
});
// ------------------------------------

// 设置安全密钥
app.post('/api/user/secret-key', requireLogin, async (req, res) => {
    const { currentPassword, newSecretKey } = req.body;
    if (!currentPassword || !newSecretKey) {
        return res.status(400).json({ error: '当前密码和新密钥不能为空' });
    }

    const db = readDB();
    const user = db.users.find(u => u.id === req.session.userId);
    if (!user) return res.status(404).json({ error: '用户不存在' });

    const valid = await comparePassword(currentPassword, user.password);
    if (!valid) return res.status(401).json({ error: '当前密码错误' });

    user.secretKey = await hashPassword(newSecretKey);
    writeDB(db);
    res.json({ success: true });
});

// 设置胁迫密码
app.post('/api/user/duress-password', requireLogin, async (req, res) => {
    const { currentPassword, newDuressPassword } = req.body;
    if (!currentPassword) {
        return res.status(400).json({ error: '请输入当前密码' });
    }

    const db = readDB();
    const user = db.users.find(u => u.id === req.session.userId);
    if (!user) return res.status(404).json({ error: '用户不存在' });

    const valid = await comparePassword(currentPassword, user.password);
    if (!valid) return res.status(401).json({ error: '当前密码错误' });

    if (newDuressPassword) {
        const isSameAsNormal = await comparePassword(newDuressPassword, user.password);
        if (isSameAsNormal) {
            return res.status(400).json({ error: '胁迫密码不能与登录密码相同' });
        }
        user.duressPasswordHash = await hashPassword(newDuressPassword);
    } else {
        user.duressPasswordHash = null;
    }

    writeDB(db);
    res.json({ success: true, hasDuress: !!user.duressPasswordHash });
});

// 通过密钥重置密码
app.post('/api/user/reset-password', async (req, res) => {
    const { username, secretKey, newPassword } = req.body;
    if (!username || !secretKey || !newPassword) {
        return res.status(400).json({ error: '请填写完整信息' });
    }
    if (newPassword.length < 6) {
        return res.status(400).json({ error: '新密码至少6位' });
    }

    const db = readDB();
    const user = db.users.find(u => u.username === username);
    if (!user) return res.status(404).json({ error: '用户不存在' });
    if (!user.secretKey) return res.status(400).json({ error: '该用户未设置密钥，无法重置' });

    const valid = await comparePassword(secretKey, user.secretKey);
    if (!valid) return res.status(401).json({ error: '密钥错误' });

    user.password = await hashPassword(newPassword);
    user.rememberToken = null;
    user.rememberTokenExpires = null;
    writeDB(db);
    res.json({ success: true });
});

// 设置背景
app.post('/api/user/background', requireLogin, (req, res) => {
    const { background } = req.body;
    if (!background) return res.status(400).json({ error: '缺少背景参数' });

    const db = readDB();
    const user = db.users.find(u => u.id === req.session.userId);
    if (!user) return res.status(404).json({ error: '用户不存在' });

    if (!user.settings) user.settings = {};
    user.settings.background = background;
    writeDB(db);
    res.json({ success: true, background });
});

// 上传背景图片
app.post('/api/user/background/upload', requireLogin, uploadBackground.single('background'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: '没有文件' });

    const db = readDB();
    const user = db.users.find(u => u.id === req.session.userId);
    if (!user) return res.status(404).json({ error: '用户不存在' });

    if (!user.settings) user.settings = {};
    user.settings.background = `url(/user-content/${user.id}/background.jpg?t=${Date.now()})`;
    writeDB(db);
    res.json({ success: true, background: user.settings.background });
});

// 头像上传
app.post('/api/user/avatar', requireLogin, uploadAvatar.single('avatar'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: '没有文件' });

    const db = readDB();
    const user = db.users.find(u => u.id === req.session.userId);
    if (!user) return res.status(404).json({ error: '用户不存在' });

    const oldAvatarPath = path.join(CONFIG.UPLOAD_ROOT, user.id, 'avatar.jpg');
    if (fs.existsSync(oldAvatarPath) && oldAvatarPath !== req.file.path) {
        try { fs.unlinkSync(oldAvatarPath); } catch (e) { console.warn(e); }
    }

    res.json({ success: true, avatarUrl: `/user-content/${user.id}/avatar.jpg?t=${Date.now()}` });
});

// 获取头像URL
app.get('/api/user/avatar', requireLogin, (req, res) => {
    const userId = req.session.userId;
    const avatarPath = path.join(CONFIG.UPLOAD_ROOT, userId, 'avatar.jpg');
    if (fs.existsSync(avatarPath)) {
        res.json({ avatarUrl: `/user-content/${userId}/avatar.jpg?t=${Date.now()}` });
    } else {
        res.json({ avatarUrl: null });
    }
});

// 删除头像
app.delete('/api/user/avatar', requireLogin, (req, res) => {
    const userId = req.session.userId;
    const avatarPath = path.join(CONFIG.UPLOAD_ROOT, userId, 'avatar.jpg');
    if (fs.existsSync(avatarPath)) {
        try {
            fs.unlinkSync(avatarPath);
        } catch (e) {
            return res.status(500).json({ error: '删除失败' });
        }
    }
    res.json({ success: true });
});

// 获取配额信息
app.get('/api/user/quota', requireLogin, (req, res) => {
    const db = readDB();
    const user = db.users.find(u => u.id === req.session.userId);
    if (!user) return res.status(404).json({ error: '用户不存在' });
    const used = getUserUsedSize(user.id);
    res.json({ quota: user.quota || 0, used });
});

// 设置配额
app.post('/api/user/quota', requireLogin, (req, res) => {
    const { quotaGB } = req.body;
    if (quotaGB === undefined || quotaGB === '') return res.status(400).json({ error: '请填写配额' });
    const quotaGBNum = parseInt(quotaGB);
    if (isNaN(quotaGBNum) || quotaGBNum < 0) return res.status(400).json({ error: '配额必须是非负整数' });
    const quotaBytes = quotaGBNum * 1024 * 1024 * 1024;

    const db = readDB();
    const user = db.users.find(u => u.id === req.session.userId);
    if (!user) return res.status(404).json({ error: '用户不存在' });
    user.quota = quotaBytes;
    writeDB(db);
    res.json({ success: true, quota: user.quota });
});

// 注销账户
app.post('/api/user/delete', requireLogin, async (req, res) => {
    const { password } = req.body;
    if (!password) return res.status(400).json({ error: '请输入密码' });

    const db = readDB();
    const user = db.users.find(u => u.id === req.session.userId);
    if (!user) return res.status(404).json({ error: '用户不存在' });
    if (user.username === 'root') return res.status(403).json({ error: '管理员账户不可注销' });

    const valid = await comparePassword(password, user.password);
    if (!valid) return res.status(401).json({ error: '密码错误' });

    const userFiles = db.files.filter(f => f.userId === user.id);
    for (const file of userFiles) {
        if (file.savedPath) {
            try { fs.unlinkSync(file.savedPath); } catch (e) { console.warn(e); }
        } else if (file.isFolder && file.physicalPath) {
            try { deleteFolderRecursive(file.physicalPath); } catch (e) { console.warn(e); }
        }
    }
    db.files = db.files.filter(f => f.userId !== user.id);
    db.users = db.users.filter(u => u.id !== user.id);
    writeDB(db);

    req.session.destroy();
    res.clearCookie('remember_token');
    res.json({ success: true });
});

// 新建文件夹
app.post('/api/folder', requireLogin, (req, res) => {
    const { name, parentId } = req.body;
    if (!name) return res.status(400).json({ error: '文件夹名称不能为空' });
    const folderName = name.trim();

    const db = readDB();
    const userId = req.session.userId;
    let physicalPath = path.join(CONFIG.UPLOAD_ROOT, userId);

    if (parentId) {
        const parentFolder = db.files.find(f => f.id === parentId && f.userId === userId && f.isFolder);
        if (parentFolder) {
            if (parentFolder.protected) {
                return res.status(403).json({ error: '父文件夹受保护，不能在此新建文件夹' });
            }
            physicalPath = parentFolder.physicalPath || path.join(CONFIG.UPLOAD_ROOT, userId, parentFolder.name);
        } else {
            return res.status(404).json({ error: '父文件夹不存在' });
        }
    }

    const folderPhysicalPath = path.join(physicalPath, folderName);

    if (fs.existsSync(folderPhysicalPath)) {
        return res.status(400).json({ error: '文件夹已存在' });
    }

    try {
        fs.mkdirSync(folderPhysicalPath, { recursive: true });
    } catch (err) {
        console.error("Failed to create folder:", err);
        return res.status(500).json({ error: '创建文件夹失败' });
    }

    const newFolder = {
        id: uuidv4(),
        userId,
        isFolder: true,
        name: folderName,
        size: 0,
        date: new Date().toISOString().split('T')[0],
        uploadTime: new Date().toISOString(),
        parentId: parentId || null,
        physicalPath: folderPhysicalPath,
        protected: false,
        passwordHash: null
    };
    db.files.push(newFolder);
    writeDB(db);
    res.json({ success: true, folder: newFolder });
});

// 获取文件列表
app.get('/api/files', requireLogin, (req, res) => {
    const db = readDB();
    const userId = req.session.userId;
    const parentId = req.query.parentId || null;

    if (parentId) {
        const parentFolder = db.files.find(f => f.id === parentId && f.userId === userId && f.isFolder);
        if (parentFolder && parentFolder.passwordHash) {
            const unlocked = req.session.unlockedFolders || [];
            if (!unlocked.includes(parentId)) {
                return res.status(403).json({ 
                    needPassword: true, 
                    folderName: parentFolder.name,
                    error: '此文件夹需要密码' 
                });
            }
        }
    }

    let userFiles = db.files.filter(f => f.userId === userId);
    userFiles = userFiles.filter(f => (f.parentId || null) === parentId);

    const fileList = userFiles.map(f => {
        if (f.isFolder) {
            return {
                id: f.id,
                name: f.name,
                isFolder: true,
                size: 0,
                date: f.date,
                mimeType: null,
                parentId: f.parentId,
                protected: f.protected || false,
                hasPassword: !!f.passwordHash
            };
        } else {
            return {
                id: f.id,
                name: f.displayPath || f.originalName,
                size: f.size,
                date: f.uploadTime.split('T')[0],
                mimeType: f.mimeType,
                parentId: f.parentId || null
            };
        }
    });
    res.json(fileList);
});

// 全局搜索（修复版）
app.get('/api/search', requireLogin, (req, res) => {
    const { q } = req.query;
    if (!q || q.trim() === '') {
        return res.json([]);
    }
    const keyword = q.trim().toLowerCase();
    const db = readDB();
    const userId = req.session.userId;

    const userFiles = db.files.filter(f => f.userId === userId);
    const results = userFiles
        .filter(f => {
            const searchName = f.isFolder ? f.name : (f.originalName || f.displayPath || '');
            return searchName.toLowerCase().includes(keyword);
        })
        .map(f => {
            const item = {
                id: f.id,
                name: f.isFolder ? f.name : (f.displayPath || f.originalName),
                isFolder: f.isFolder,
                size: f.isFolder ? 0 : f.size,
                date: f.isFolder ? f.date : f.uploadTime.split('T')[0],
                mimeType: f.isFolder ? null : f.mimeType,
                parentId: f.parentId,
                protected: f.isFolder ? (f.protected || false) : false,
                hasPassword: f.isFolder ? !!f.passwordHash : false,
            };
            // 计算完整路径（用于显示）
            let pathParts = [];
            let current = f;
            while (current.parentId) {
                const parent = db.files.find(p => p.id === current.parentId && p.userId === userId && p.isFolder);
                if (!parent) break;
                pathParts.unshift(parent.name);
                current = parent;
            }
            item.fullPath = pathParts.length ? '/' + pathParts.join('/') : '/';
            return item;
        });
    res.json(results);
});

// 上传文件（增加祖先保护检查）
app.post('/api/upload', requireLogin, upload.array('files', 1000), (req, res) => {
    const uploadedFiles = req.files || [];
    if (uploadedFiles.length === 0) return res.status(400).json({ error: '没有文件' });

    const db = readDB();
    const userId = req.session.userId;
    const user = db.users.find(u => u.id === userId);
    if (!user) return res.status(404).json({ error: '用户不存在' });

    const parentId = req.body.parentId || null;

    // 检查所有祖先文件夹是否受保护
    if (parentId && isAnyAncestorProtected(db, userId, parentId)) {
        uploadedFiles.forEach(file => {
            try { fs.unlinkSync(file.path); } catch (e) { console.warn(e); }
        });
        return res.status(403).json({ error: '目标文件夹或其祖先受保护，不能上传文件' });
    }

    const quota = user.quota || 0;
    if (quota > 0) {
        const used = getUserUsedSize(userId);
        const uploadTotal = uploadedFiles.reduce((acc, f) => acc + f.size, 0);
        if (used + uploadTotal > quota) {
            uploadedFiles.forEach(file => {
                try { fs.unlinkSync(file.path); } catch (e) { console.warn(e); }
            });
            return res.status(400).json({ error: '存储空间不足' });
        }
    }

    const newFiles = [];
    uploadedFiles.forEach(file => {
        const decodedName = decodeFileName(file.originalname);
        let decodedDisplayPath = file.webkitRelativePath ? decodeFileName(file.webkitRelativePath) : decodedName;
        newFiles.push({
            id: uuidv4(),
            userId,
            isFolder: false,
            originalName: decodedName,
            displayPath: decodedDisplayPath,
            savedPath: file.path,
            size: file.size,
            mimeType: file.mimetype,
            uploadTime: new Date().toISOString(),
            parentId: parentId
        });
    });

    db.files.push(...newFiles);
    writeDB(db);
    res.json({ success: true, files: newFiles });
});

// 设置文件夹只读保护
app.post('/api/folder/:id/protect', requireLogin, (req, res) => {
    const { protected } = req.body;
    const db = readDB();
    const folder = db.files.find(f => f.id === req.params.id && f.userId === req.session.userId && f.isFolder);
    if (!folder) return res.status(404).json({ error: '文件夹不存在' });

    folder.protected = !!protected;
    writeDB(db);
    res.json({ success: true, protected: folder.protected });
});

// 设置/修改文件夹密码
app.post('/api/folder/:id/password', requireLogin, async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    const db = readDB();
    const userId = req.session.userId;
    const folder = db.files.find(f => f.id === req.params.id && f.userId === userId && f.isFolder);
    if (!folder) return res.status(404).json({ error: '文件夹不存在' });

    if (folder.passwordHash) {
        if (!currentPassword) return res.status(400).json({ error: '请输入当前密码' });
        const valid = await comparePassword(currentPassword, folder.passwordHash);
        if (!valid) return res.status(401).json({ error: '当前密码错误' });
    }

    if (newPassword) {
        folder.passwordHash = await hashPassword(newPassword);
    } else {
        folder.passwordHash = null;
    }

    writeDB(db);
    res.json({ success: true, hasPassword: !!folder.passwordHash });
});

// 解锁受密码保护的文件夹
app.post('/api/folder/:id/unlock', requireLogin, async (req, res) => {
    const { password } = req.body;
    if (!password) return res.status(400).json({ error: '请输入密码' });

    const db = readDB();
    const userId = req.session.userId;
    const folder = db.files.find(f => f.id === req.params.id && f.userId === userId && f.isFolder);
    if (!folder) return res.status(404).json({ error: '文件夹不存在' });
    if (!folder.passwordHash) return res.status(400).json({ error: '此文件夹未设置密码' });

    const valid = await comparePassword(password, folder.passwordHash);
    if (!valid) return res.status(401).json({ error: '密码错误' });

    if (!req.session.unlockedFolders) req.session.unlockedFolders = [];
    if (!req.session.unlockedFolders.includes(folder.id)) {
        req.session.unlockedFolders.push(folder.id);
    }
    res.json({ success: true });
});

// 重命名
app.put('/api/files/:id', requireLogin, (req, res) => {
    const { name } = req.body;
    if (!name) return res.status(400).json({ error: '名称不能为空' });
    const newName = name.trim();

    const db = readDB();
    const userId = req.session.userId;
    const item = db.files.find(f => f.id === req.params.id && f.userId === userId);
    if (!item) return res.status(404).json({ error: '文件/文件夹不存在' });

    if (item.isFolder && item.protected) {
        return res.status(403).json({ error: '受保护文件夹不能重命名' });
    }
    if (!item.isFolder && item.parentId && isFolderProtected(db, userId, item.parentId)) {
        return res.status(403).json({ error: '所在文件夹受保护，无法重命名文件' });
    }

    if (item.isFolder) {
        const oldPhysicalPath = item.physicalPath;
        if (oldPhysicalPath && fs.existsSync(oldPhysicalPath)) {
            const parentDir = path.dirname(oldPhysicalPath);
            const newPhysicalPath = path.join(parentDir, newName);
            try {
                fs.renameSync(oldPhysicalPath, newPhysicalPath);
                item.physicalPath = newPhysicalPath;
                updateChildrenPaths(db, userId, oldPhysicalPath, newPhysicalPath);
            } catch (err) {
                console.error("Rename folder error:", err);
                return res.status(500).json({ error: '物理目录重命名失败' });
            }
        }
        item.name = newName;
    } else {
        const oldExt = path.extname(item.originalName);
        const newBase = newName.endsWith(oldExt) ? newName : newName + oldExt;
        if (item.savedPath && fs.existsSync(item.savedPath)) {
            const parentDir = path.dirname(item.savedPath);
            const newFilePath = path.join(parentDir, `${Date.now()}-${uuidv4()}-${newBase}`);
            try {
                fs.renameSync(item.savedPath, newFilePath);
                item.savedPath = newFilePath;
            } catch (err) {
                console.error("Rename file error:", err);
                return res.status(500).json({ error: '物理文件重命名失败' });
            }
        }
        item.originalName = newBase;
        if (item.displayPath) {
            const oldDisplayPath = item.displayPath;
            const dir = path.dirname(oldDisplayPath);
            item.displayPath = dir === '.' ? newBase : path.join(dir, newBase);
        }
    }
    writeDB(db);
    res.json({ success: true, item });
});

// 下载文件（增加密码检查）
app.get('/api/files/:id', requireLogin, (req, res) => {
    const db = readDB();
    const userId = req.session.userId;
    const fileId = req.params.id;

    const access = checkFileAccess(db, userId, fileId, req.session);
    if (!access.ok) {
        if (access.needPassword) {
            return res.status(403).json({ needPassword: true, folderId: access.folderId, folderName: access.folderName });
        }
        return res.status(access.status).json({ error: access.error });
    }

    const file = db.files.find(f => f.id === fileId && f.userId === userId && !f.isFolder);
    if (!file) return res.status(404).json({ error: '文件不存在' });
    const filename = path.basename(file.displayPath || file.originalName);
    res.download(file.savedPath, filename);
});

// 预览图片（增加密码检查）
app.get('/api/preview/:id', requireLogin, (req, res) => {
    const db = readDB();
    const userId = req.session.userId;
    const fileId = req.params.id;

    const access = checkFileAccess(db, userId, fileId, req.session);
    if (!access.ok) {
        if (access.needPassword) {
            return res.status(403).json({ needPassword: true, folderId: access.folderId, folderName: access.folderName });
        }
        return res.status(access.status).json({ error: access.error });
    }

    const file = db.files.find(f => f.id === fileId && f.userId === userId && !f.isFolder);
    if (!file || !file.mimeType?.startsWith('image/')) return res.status(404).json({ error: '不是图片' });
    res.setHeader('Content-Type', file.mimeType);
    res.sendFile(file.savedPath);
});

// 播放音视频（增加密码检查）
app.get('/api/play/:id', requireLogin, (req, res) => {
    const db = readDB();
    const userId = req.session.userId;
    const fileId = req.params.id;

    const access = checkFileAccess(db, userId, fileId, req.session);
    if (!access.ok) {
        if (access.needPassword) {
            return res.status(403).json({ needPassword: true, folderId: access.folderId, folderName: access.folderName });
        }
        return res.status(access.status).json({ error: access.error });
    }

    const file = db.files.find(f => f.id === fileId && f.userId === userId && !f.isFolder);
    if (!file || (!file.mimeType?.startsWith('video/') && !file.mimeType?.startsWith('audio/'))) {
        return res.status(404).json({ error: '不是音视频' });
    }
    res.setHeader('Content-Type', file.mimeType);
    res.sendFile(file.savedPath);
});

// 获取文本文件内容（增加密码检查）
app.get('/api/text/:id', requireLogin, (req, res) => {
    const db = readDB();
    const userId = req.session.userId;
    const fileId = req.params.id;

    const access = checkFileAccess(db, userId, fileId, req.session);
    if (!access.ok) {
        if (access.needPassword) {
            return res.status(403).json({ needPassword: true, folderId: access.folderId, folderName: access.folderName });
        }
        return res.status(access.status).json({ error: access.error });
    }

    const file = db.files.find(f => f.id === fileId && f.userId === userId && !f.isFolder);
    if (!file) return res.status(404).json({ error: '文件不存在' });
    if (!file.mimeType || !file.mimeType.startsWith('text/')) {
        return res.status(400).json({ error: '不是文本文件' });
    }
    const MAX_TEXT_SIZE = 10 * 1024 * 1024; // 10MB
    if (file.size > MAX_TEXT_SIZE) {
        return res.status(400).json({ error: '文件过大，无法在线编辑' });
    }
    try {
        const content = fs.readFileSync(file.savedPath, 'utf-8');
        res.setHeader('Content-Type', 'text/plain; charset=utf-8');
        res.send(content);
    } catch (err) {
        console.error('读取文本文件失败:', err);
        res.status(500).json({ error: '读取文件失败' });
    }
});

// 保存文本文件内容（增加密码检查）
app.put('/api/text/:id', requireLogin, async (req, res) => {
    const { content } = req.body;
    if (content === undefined) return res.status(400).json({ error: '缺少内容' });

    const db = readDB();
    const userId = req.session.userId;
    const fileId = req.params.id;

    const access = checkFileAccess(db, userId, fileId, req.session);
    if (!access.ok) {
        if (access.needPassword) {
            return res.status(403).json({ needPassword: true, folderId: access.folderId, folderName: access.folderName });
        }
        return res.status(access.status).json({ error: access.error });
    }

    const file = db.files.find(f => f.id === fileId && f.userId === userId && !f.isFolder);
    if (!file) return res.status(404).json({ error: '文件不存在' });
    if (!file.mimeType || !file.mimeType.startsWith('text/')) {
        return res.status(400).json({ error: '不是文本文件' });
    }

    if (file.parentId && isFolderProtected(db, userId, file.parentId)) {
        return res.status(403).json({ error: '所在文件夹受保护，无法编辑' });
    }

    try {
        fs.writeFileSync(file.savedPath, content, 'utf-8');
        const stats = fs.statSync(file.savedPath);
        file.size = stats.size;
        file.uploadTime = new Date().toISOString();
        writeDB(db);
        res.json({ success: true });
    } catch (err) {
        console.error('写入文本文件失败:', err);
        res.status(500).json({ error: '保存文件失败' });
    }
});

// 删除文件/文件夹
app.delete('/api/files/:id', requireLogin, (req, res) => {
    const db = readDB();
    const item = db.files.find(f => f.id === req.params.id && f.userId === req.session.userId);
    if (!item) return res.status(404).json({ error: '不存在' });

    if (item.isFolder && item.protected) {
        return res.status(403).json({ error: '受保护文件夹不能删除' });
    }
    if (!item.isFolder && item.parentId && isFolderProtected(db, req.session.userId, item.parentId)) {
        return res.status(403).json({ error: '所在文件夹受保护，无法删除文件' });
    }

    if (item.isFolder) {
        deleteFolderAndChildren(db, req.session.userId, item.id);
    } else {
        if (item.savedPath) {
            try { fs.unlinkSync(item.savedPath); } catch (err) { console.warn(err); }
        }
        db.files = db.files.filter(f => f.id !== req.params.id);
    }

    writeDB(db);
    res.json({ success: true });
});

// 分享链接（增加祖先密码检查）
app.post('/api/share/:id', requireLogin, (req, res) => {
    const db = readDB();
    const userId = req.session.userId;
    const file = db.files.find(f => f.id === req.params.id && f.userId === userId && !f.isFolder);
    if (!file) return res.status(404).json({ error: '文件不存在' });

    // 检查祖先文件夹是否有密码且未解锁
    let parentId = file.parentId;
    while (parentId) {
        const parent = db.files.find(f => f.id === parentId && f.userId === userId && f.isFolder);
        if (!parent) break;
        if (parent.passwordHash && !(req.session.unlockedFolders || []).includes(parent.id)) {
            return res.status(403).json({ error: '文件位于受密码保护的文件夹内，无法分享' });
        }
        parentId = parent.parentId;
    }

    const token = uuidv4();
    db.shares.push({ token, fileId: file.id, createdAt: new Date().toISOString() });
    writeDB(db);
    res.json({ shareUrl: `/s/${token}` });
});

app.get('/s/:token', (req, res) => {
    const db = readDB();
    const share = db.shares.find(s => s.token === req.params.token);
    if (!share) return res.status(404).send('链接无效');
    const file = db.files.find(f => f.id === share.fileId);
    if (!file) return res.status(404).send('文件已不存在');
    const filename = path.basename(file.displayPath || file.originalName);
    res.download(file.savedPath, filename);
});

// 管理员统计
app.get('/api/admin/stats', requireLogin, requireAdmin, (req, res) => {
    const db = readDB();
    const totalUsers = db.users.length;
    const totalFiles = db.files.filter(f => !f.isFolder).length;
    const totalSize = db.files.reduce((acc, f) => acc + (f.size || 0), 0);
    res.json({ totalUsers, totalFiles, totalFileSize: totalSize });
});

// 重启服务器
app.post('/api/admin/restart', requireLogin, requireAdmin, (req, res) => {
    res.json({ success: true, message: '服务器重启中...' });
    setTimeout(() => process.exit(1), 1000);
});

// 404 处理
app.use((req, res) => {
    if (req.path.startsWith('/api/')) {
        return res.status(404).json({ error: 'API endpoint not found' });
    }
    if (req.path === '/' || req.path === '/index.html' || req.path === '/login.html') {
        const indexPath = path.join(__dirname, 'public', 'index.html');
        if (fs.existsSync(indexPath)) {
            return res.sendFile(indexPath);
        }
    }
    res.status(404).send(`
        <html>
        <head><title>404 Not Found</title></head>
        <body>
            <h1>404 Not Found</h1>
            <p>The requested URL ${req.path} was not found on this server.</p>
            <p><a href="/">Go Home</a></p>
        </body>
        </html>
    `);
});

// 错误处理
app.use((err, req, res, next) => {
    console.error("Unhandled Error:", err.stack);
    res.status(500).json({ error: err.message || '服务器内部错误' });
});

// 启动服务器
app.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ HomeCloud 服务器运行中`);
    console.log(`➜ 本地: http://localhost:${PORT}`);
    console.log(`➜ 内网: 请查看前端显示IP`);
    console.log(`➜ 管理员: root / root (密码已哈希)`);
});

module.exports = app;
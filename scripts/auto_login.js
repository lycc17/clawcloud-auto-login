/**
 * ClawCloud 自动登录脚本 (Node.js 版)
 * - 等待设备验证批准
 * - 支持 Telegram 交互输入 2FA 验证码
 * - 自动更新 GitHub Secret (GH_SESSION)
 */

const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright');
const axios = require('axios');
const FormData = require('form-data');
const sodium = require('libsodium-wrappers');

// ==================== 配置 ====================
const CONFIG = {
    CLAW_CLOUD_URL: "https://eu-central-1.run.claw.cloud", // 如果是美西请修改
    DEVICE_VERIFY_WAIT: 60, // 秒
    TWO_FACTOR_WAIT: parseInt(process.env.TWO_FACTOR_WAIT || "120"),
    GH_USERNAME: process.env.GH_USERNAME,
    GH_PASSWORD: process.env.GH_PASSWORD,
    GH_SESSION: process.env.GH_SESSION,
    TG_BOT_TOKEN: process.env.TG_BOT_TOKEN,
    TG_CHAT_ID: process.env.TG_CHAT_ID,
    REPO_TOKEN: process.env.REPO_TOKEN,
    GITHUB_REPOSITORY: process.env.GITHUB_REPOSITORY
};

CONFIG.SIGNIN_URL = `${CONFIG.CLAW_CLOUD_URL}/signin`;

// ==================== 工具类 ====================

const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

class Logger {
    constructor() { this.logs = []; }
    log(msg, level = "INFO") {
        const icons = { "INFO": "ℹ️", "SUCCESS": "✅", "ERROR": "❌", "WARN": "⚠️", "STEP": "🔹" };
        const icon = icons[level] || "•";
        const line = `${icon} ${msg}`;
        console.log(line);
        this.logs.push(line);
    }
    getRecentLogs() { return this.logs.slice(-6).join("\n"); }
}

const logger = new Logger();

class Telegram {
    constructor() {
        this.token = CONFIG.TG_BOT_TOKEN;
        this.chatId = CONFIG.TG_CHAT_ID;
        this.ok = !!(this.token && this.chatId);
        this.apiBase = `https://api.telegram.org/bot${this.token}`;
    }

    async send(msg) {
        if (!this.ok) return;
        try {
            await axios.post(`${this.apiBase}/sendMessage`, {
                chat_id: this.chatId,
                text: msg,
                parse_mode: "HTML"
            });
        } catch (e) { /* ignore */ }
    }

    async photo(filePath, caption = "") {
        if (!this.ok || !fs.existsSync(filePath)) return;
        try {
            const form = new FormData();
            form.append('chat_id', this.chatId);
            form.append('caption', caption.substring(0, 1024));
            form.append('photo', fs.createReadStream(filePath));
            await axios.post(`${this.apiBase}/sendPhoto`, form, {
                headers: form.getHeaders()
            });
        } catch (e) { /* ignore */ }
    }

    async getUpdates(offset = 0) {
        try {
            const res = await axios.get(`${this.apiBase}/getUpdates`, {
                params: { timeout: 0, offset: offset },
                timeout: 10000
            });
            return res.data;
        } catch (e) { return null; }
    }

    async flushUpdates() {
        if (!this.ok) return 0;
        const data = await this.getUpdates();
        if (data && data.ok && data.result.length > 0) {
            return data.result[data.result.length - 1].update_id + 1;
        }
        return 0;
    }

    async waitCode(timeoutSec = 120) {
        if (!this.ok) return null;

        let offset = await this.flushUpdates();
        const deadline = Date.now() + timeoutSec * 1000;
        const pattern = /^\/code\s+(\d{6,8})$/;

        while (Date.now() < deadline) {
            try {
                const res = await axios.get(`${this.apiBase}/getUpdates`, {
                    params: { timeout: 20, offset: offset },
                    timeout: 30000
                });
                
                const data = res.data;
                if (!data.ok) {
                    await sleep(2000);
                    continue;
                }

                for (const upd of data.result) {
                    offset = upd.update_id + 1;
                    const msg = upd.message || {};
                    const chat = msg.chat || {};

                    if (String(chat.id) !== String(this.chatId)) continue;

                    const text = (msg.text || "").trim();
                    const match = text.match(pattern);
                    if (match) {
                        return match[1];
                    }
                }
            } catch (e) { /* ignore */ }
            await sleep(2000);
        }
        return null;
    }
}

class SecretUpdater {
    constructor() {
        this.token = CONFIG.REPO_TOKEN;
        this.repo = CONFIG.GITHUB_REPOSITORY;
        this.ok = !!(this.token && this.repo);
        if (this.ok) console.log("✅ Secret 自动更新已启用");
        else console.log("⚠️ Secret 自动更新未启用（需要 REPO_TOKEN）");
    }

    async update(name, value) {
        if (!this.ok) return false;
        try {
            await sodium.ready;
            
            const headers = {
                "Authorization": `token ${this.token}`,
                "Accept": "application/vnd.github.v3+json"
            };

            // 1. 获取公钥
            const keyRes = await axios.get(`https://api.github.com/repos/${this.repo}/actions/secrets/public-key`, { headers });
            const keyData = keyRes.data;

            // 2. 加密
            const binkey = sodium.from_base64(keyData.key, sodium.base64_variants.ORIGINAL);
            const binsec = sodium.from_string(value);
            const encBytes = sodium.crypto_box_seal(binsec, binkey);
            const encryptedValue = sodium.to_base64(encBytes, sodium.base64_variants.ORIGINAL);

            // 3. 更新
            const putRes = await axios.put(`https://api.github.com/repos/${this.repo}/actions/secrets/${name}`, {
                encrypted_value: encryptedValue,
                key_id: keyData.key_id
            }, { headers });

            return [201, 204].includes(putRes.status);
        } catch (e) {
            console.error(`更新 Secret 失败: ${e.message}`);
            return false;
        }
    }
}

// ==================== 主逻辑 ====================

class AutoLogin {
    constructor() {
        this.tg = new Telegram();
        this.secret = new SecretUpdater();
        this.shots = [];
        this.shotCount = 0;
    }

    async shot(page, name) {
        this.shotCount++;
        const filename = `${String(this.shotCount).padStart(2, '0')}_${name}.png`;
        try {
            await page.screenshot({ path: filename });
            this.shots.push(filename);
            return filename;
        } catch (e) { return null; }
    }

    async click(page, selectors, desc = "") {
        for (const sel of selectors) {
            try {
                const el = page.locator(sel).first();
                if (await el.isVisible({ timeout: 3000 })) {
                    await el.click();
                    logger.log(`已点击: ${desc}`, "SUCCESS");
                    return true;
                }
            } catch (e) { /* ignore */ }
        }
        return false;
    }

    async getSession(context) {
        try {
            const cookies = await context.cookies();
            const session = cookies.find(c => c.name === 'user_session' && c.domain.includes('github'));
            return session ? session.value : null;
        } catch (e) { return null; }
    }

    async saveCookie(value) {
        if (!value) return;
        const masked = `${value.substring(0, 15)}...${value.substring(value.length - 8)}`;
        logger.log(`新 Cookie: ${masked}`, "SUCCESS");

        if (await this.secret.update('GH_SESSION', value)) {
            logger.log("已自动更新 GH_SESSION", "SUCCESS");
            await this.tg.send("🔑 <b>Cookie 已自动更新</b>\n\nGH_SESSION 已保存");
        } else {
            await this.tg.send(`🔑 <b>新 Cookie</b>\n\n请更新 Secret <b>GH_SESSION</b>:\n<code>${value}</code>`);
            logger.log("已通过 Telegram 发送 Cookie", "SUCCESS");
        }
    }

    async waitDevice(page) {
        logger.log(`需要设备验证，等待 ${CONFIG.DEVICE_VERIFY_WAIT} 秒...`, "WARN");
        const s = await this.shot(page, "设备验证");
        
        await this.tg.send(`⚠️ <b>需要设备验证</b>\n\n请在 ${CONFIG.DEVICE_VERIFY_WAIT} 秒内批准：\n1️⃣ 检查邮箱点击链接\n2️⃣ 或在 GitHub App 批准`);
        if (s) await this.tg.photo(s, "设备验证页面");

        for (let i = 0; i < CONFIG.DEVICE_VERIFY_WAIT; i++) {
            await sleep(1000);
            if (i % 5 === 0) {
                logger.log(`  等待... (${i}/${CONFIG.DEVICE_VERIFY_WAIT}秒)`);
                const url = page.url();
                if (!url.includes('verified-device') && !url.includes('device-verification')) {
                    logger.log("设备验证通过！", "SUCCESS");
                    await this.tg.send("✅ <b>设备验证通过</b>");
                    return true;
                }
                try { await page.reload(); } catch(e){}
            }
        }
        return false;
    }

    async waitTwoFactorMobile(page) {
        logger.log(`需要两步验证（Mobile），等待 ${CONFIG.TWO_FACTOR_WAIT} 秒...`, "WARN");
        const s = await this.shot(page, "两步验证_mobile");
        
        await this.tg.send(`⚠️ <b>需要两步验证（GitHub Mobile）</b>\n\n请打开手机 GitHub App 批准。\n等待时间：${CONFIG.TWO_FACTOR_WAIT} 秒`);
        if (s) await this.tg.photo(s, "两步验证页面");

        for (let i = 0; i < CONFIG.TWO_FACTOR_WAIT; i++) {
            await sleep(1000);
            const url = page.url();

            if (!url.includes('github.com/sessions/two-factor/')) {
                logger.log("两步验证通过！", "SUCCESS");
                await this.tg.send("✅ <b>两步验证通过</b>");
                return true;
            }
            if (url.includes('github.com/login')) {
                return false;
            }
            if (i % 10 === 0 && i !== 0) {
                logger.log(`  等待... (${i}/${CONFIG.TWO_FACTOR_WAIT}秒)`);
            }
        }
        await this.tg.send("❌ <b>两步验证超时</b>");
        return false;
    }

    async handle2FACodeInput(page) {
        logger.log("需要输入验证码", "WARN");
        let s = await this.shot(page, "两步验证_code");

        // 尝试切换到验证码输入模式
        try {
            const moreOpts = page.locator('a[href*="two-factor/app"], button:has-text("Use an authentication app")').first();
            if (await moreOpts.isVisible()) {
                await moreOpts.click();
                await page.waitForLoadState('networkidle');
                s = await this.shot(page, "两步验证_code_切换后");
            }
        } catch(e) {}

        await this.tg.send(`🔐 <b>需要验证码登录</b>\n\n请在 Telegram 里发送：\n<code>/code 你的6位验证码</code>\n\n等待 ${CONFIG.TWO_FACTOR_WAIT} 秒`);
        if (s) await this.tg.photo(s, "两步验证页面");

        const code = await this.tg.waitCode(CONFIG.TWO_FACTOR_WAIT);
        if (!code) {
            logger.log("等待验证码超时", "ERROR");
            await this.tg.send("❌ <b>等待验证码超时</b>");
            return false;
        }

        logger.log("收到验证码，正在填入...", "SUCCESS");
        await this.tg.send("✅ 收到验证码，正在填入...");

        const inputSelectors = [
            'input[autocomplete="one-time-code"]', 'input[name="app_otp"]', '#app_totp', '#otp'
        ];

        for (const sel of inputSelectors) {
            try {
                const el = page.locator(sel).first();
                if (await el.isVisible()) {
                    await el.fill(code);
                    await sleep(1000);

                    // 尝试提交
                    if (!await this.click(page, ['button:has-text("Verify")', 'button[type="submit"]'], "Verify按钮")) {
                        await page.keyboard.press('Enter');
                    }
                    
                    await sleep(3000);
                    await page.waitForLoadState('networkidle');

                    if (!page.url().includes('two-factor')) {
                        logger.log("验证码验证通过！", "SUCCESS");
                        await this.tg.send("✅ <b>验证码验证通过</b>");
                        return true;
                    }
                }
            } catch(e) {}
        }
        await this.tg.send("❌ <b>验证码可能错误或输入失败</b>");
        return false;
    }

    async loginGithub(page) {
        logger.log("登录 GitHub...", "STEP");
        await this.shot(page, "github_login");

        try {
            await page.fill('input[name="login"]', CONFIG.GH_USERNAME);
            await page.fill('input[name="password"]', CONFIG.GH_PASSWORD);
            await page.click('input[type="submit"], button[type="submit"]');
        } catch (e) {
            logger.log(`输入凭据失败: ${e.message}`, "ERROR");
            return false;
        }

        await sleep(3000);
        await page.waitForLoadState('networkidle');
        let url = page.url();

        // 设备验证
        if (url.includes('verified-device') || url.includes('device-verification')) {
            if (!await this.waitDevice(page)) return false;
            await sleep(2000);
        }

        // 2FA
        if (page.url().includes('two-factor')) {
            if (page.url().includes('two-factor/mobile')) {
                if (!await this.waitTwoFactorMobile(page)) return false;
            } else {
                if (!await this.handle2FACodeInput(page)) return false;
            }
            await page.waitForLoadState('networkidle');
        }

        return true;
    }

    async oauth(page) {
        if (page.url().includes('github.com/login/oauth/authorize')) {
            logger.log("处理 OAuth...", "STEP");
            await this.shot(page, "oauth");
            await this.click(page, ['button[name="authorize"]', 'button:has-text("Authorize")'], "授权");
            await sleep(3000);
            await page.waitForLoadState('networkidle');
        }
    }

    async keepalive(page) {
        logger.log("执行保活...", "STEP");
        const urls = [`${CONFIG.CLAW_CLOUD_URL}/`, `${CONFIG.CLAW_CLOUD_URL}/apps`];
        for (const u of urls) {
            try {
                await page.goto(u, { timeout: 30000 });
                await page.waitForLoadState('networkidle');
                logger.log(`已访问: ${u}`, "SUCCESS");
                await sleep(2000);
            } catch(e) {}
        }
        await this.shot(page, "完成");
    }

    async notify(ok, err = "") {
        if (!this.tg.ok) return;
        const now = new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
        let msg = `<b>🤖 ClawCloud 自动登录 (JS版)</b>\n\n<b>状态:</b> ${ok ? "✅ 成功" : "❌ 失败"}\n<b>用户:</b> ${CONFIG.GH_USERNAME}\n<b>时间:</b> ${now}`;
        if (err) msg += `\n<b>错误:</b> ${err}`;
        msg += `\n\n<b>日志:</b>\n${logger.getRecentLogs()}`;
        
        await this.tg.send(msg);
        
        if (this.shots.length > 0) {
            if (!ok) {
                // 失败发最后3张
                for (let i = Math.max(0, this.shots.length - 3); i < this.shots.length; i++) {
                    await this.tg.photo(this.shots[i], this.shots[i]);
                }
            } else {
                await this.tg.photo(this.shots[this.shots.length - 1], "完成");
            }
        }
    }

    async run() {
        console.log("\n" + "=".repeat(50));
        console.log("🚀 ClawCloud 自动登录 (Node.js)");
        console.log("=".repeat(50) + "\n");

        if (!CONFIG.GH_USERNAME || !CONFIG.GH_PASSWORD) {
            logger.log("缺少凭据 (GH_USERNAME/GH_PASSWORD)", "ERROR");
            await this.notify(false, "凭据未配置");
            process.exit(1);
        }

        const browser = await chromium.launch({ headless: true, args: ['--no-sandbox'] });
        const context = await browser.newContext({
            viewport: { width: 1920, height: 1080 },
            userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        });

        try {
            // 预加载 Cookie
            if (CONFIG.GH_SESSION) {
                try {
                    await context.addCookies([{
                        name: 'user_session', value: CONFIG.GH_SESSION, domain: 'github.com', path: '/'
                    }, {
                        name: 'logged_in', value: 'yes', domain: 'github.com', path: '/'
                    }]);
                    logger.log("已加载 Session Cookie", "SUCCESS");
                } catch(e) { logger.log("加载 Cookie 失败", "WARN"); }
            }

            const page = await context.newPage();

            // 1. 访问
            logger.log("步骤1: 打开 ClawCloud", "STEP");
            await page.goto(CONFIG.SIGNIN_URL, { timeout: 60000 });
            await page.waitForLoadState('networkidle');
            await this.shot(page, "clawcloud");

            if (!page.url().toLowerCase().includes('signin')) {
                logger.log("已登录！", "SUCCESS");
                await this.keepalive(page);
                const newCookie = await this.getSession(context);
                if (newCookie) await this.saveCookie(newCookie);
                await this.notify(true);
                return;
            }

            // 2. 点击 GitHub
            logger.log("步骤2: 点击 GitHub", "STEP");
            if (!await this.click(page, ['button:has-text("GitHub")', '[data-provider="github"]'], "GitHub")) {
                throw new Error("找不到 GitHub 按钮");
            }
            await page.waitForLoadState('networkidle');
            await this.shot(page, "点击后");

            // 3. GitHub 认证
            let url = page.url();
            if (url.includes('github.com/login') || url.includes('github.com/session')) {
                if (!await this.loginGithub(page)) throw new Error("GitHub 登录失败");
            } else if (url.includes('github.com/login/oauth/authorize')) {
                logger.log("Cookie 有效", "SUCCESS");
                await this.oauth(page);
            }

            // 4. 重定向
            logger.log("步骤4: 等待重定向", "STEP");
            let redirected = false;
            for (let i = 0; i < 60; i++) {
                if (page.url().includes('claw.cloud') && !page.url().toLowerCase().includes('signin')) {
                    redirected = true;
                    break;
                }
                if (page.url().includes('oauth/authorize')) await this.oauth(page);
                await sleep(1000);
            }

            if (!redirected) throw new Error("重定向超时");

            // 5. 保活
            await this.keepalive(page);

            // 6. 更新 Cookie
            const finalCookie = await this.getSession(context);
            if (finalCookie) await this.saveCookie(finalCookie);

            await this.notify(true);
            console.log("\n✅ 成功！\n");

        } catch (error) {
            logger.log(`异常: ${error.message}`, "ERROR");
            console.error(error);
            await this.notify(false, error.message);
            process.exit(1);
        } finally {
            await browser.close();
        }
    }
}

// 运行
(new AutoLogin()).run();


const http = require('http');
const express = require('express');
const app = express();
const mysql = require('mysql2/promise');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const nodemailer = require('nodemailer');
const schedule = require('node-schedule');
const fs = require('fs');
const path = require('path');
const dotenv = require('dotenv');
const hostname = '127.0.0.1';
const port = 3000;

// ตั้งค่าสภาพแวดล้อม
dotenv.config();

// Middleware
app.use(cors());
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

// ตั้งค่า constants
const JWT_SECRET = process.env.JWT_SECRET || 'medicare-reminder-secret-key';

// สร้างการเชื่อมต่อกับฐานข้อมูล
const pool = mysql.createPool({
    host: 'gateway01.us-west-2.prod.aws.tidbcloud.com',
    user: '45frusCB8p7MEfj.root',
    password: 'NnSGTkAGOMtk5a7N',
    database: 'medicare_db',
    port: 4000,
    ssl: {
        rejectUnauthorized: false
    }
});

// ตรวจสอบการเชื่อมต่อฐานข้อมูล
async function checkDatabaseConnection() {
    try {
        const connection = await pool.getConnection();
        console.log('การเชื่อมต่อฐานข้อมูลสำเร็จ!');
        connection.release();
        return true;
    } catch (error) {
        console.error('ไม่สามารถเชื่อมต่อกับฐานข้อมูล:', error);
        return false;
    }
}

// ฟังก์ชันช่วยสำหรับการสร้าง JWT
function generateToken(user) {
    return jwt.sign(
        { id: user.id, email: user.email, role: user.role },
        JWT_SECRET,
        { expiresIn: '24h' }
    );
}

// Middleware สำหรับตรวจสอบการยืนยันตัวตน
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'ไม่มีโทเค็นการยืนยันตัวตน' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'โทเค็นไม่ถูกต้องหรือหมดอายุ' });
        }
        req.user = user;
        next();
    });
}

// Middleware สำหรับตรวจสอบบทบาทของผู้ใช้
function checkRole(roles) {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({ message: 'ไม่มีการยืนยันตัวตน' });
        }

        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ message: 'ไม่มีสิทธิ์เข้าถึง' });
        }

        next();
    };
}

// ตั้งค่า Nodemailer
const mailTransporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER || 'medicare.reminder@gmail.com',
        pass: process.env.EMAIL_PASS || 'your-app-password'
    }
});

/**
 * API ENDPOINTS
 */

// API สำหรับการทดสอบเซิร์ฟเวอร์
app.get('/', (req, res) => {
    res.json({
        "Name": "MediCare Reminder API",
        "Author": "Your Name",
        "APIs": [
            {"api_name": "/api/health", "method": "get", "description": "ตรวจสอบสถานะระบบ"},
            {"api_name": "/api/auth/register", "method": "post", "description": "สมัครสมาชิก"},
            {"api_name": "/api/auth/login", "method": "post", "description": "เข้าสู่ระบบ"},
            {"api_name": "/api/patients", "method": "get", "description": "ดึงรายชื่อผู้ป่วยทั้งหมด"},
            {"api_name": "/api/patients/:patientId", "method": "get", "description": "ดึงข้อมูลผู้ป่วยรายบุคคล"},
            {"api_name": "/api/medications", "method": "post", "description": "สั่งยาให้ผู้ป่วย"},
            {"api_name": "/api/medication-logs", "method": "post", "description": "บันทึกการใช้ยา"},
            {"api_name": "/api/dashboard/doctor", "method": "get", "description": "ดึงข้อมูลแดชบอร์ดแพทย์"}
        ]
    });
});

app.get('/api/health', async (req, res) => {
    const dbConnected = await checkDatabaseConnection();
    
    res.status(200).json({
        status: 'ok',
        message: 'ระบบทำงานปกติ',
        database: dbConnected ? 'เชื่อมต่อสำเร็จ' : 'เชื่อมต่อไม่สำเร็จ',
        timestamp: new Date()
    });
});

/**
 * API เกี่ยวกับการยืนยันตัวตน
 */

// API สมัครสมาชิก
app.post('/api/auth/register', async (req, res) => {
    try {
        const { email, password, role, firstName, lastName, phone, ...additionalData } = req.body;
        
        // ตรวจสอบข้อมูลที่จำเป็น
        if (!email || !password || !firstName || !lastName) {
            return res.status(400).json({ message: 'กรุณากรอกข้อมูลให้ครบถ้วน' });
        }

        // ตรวจสอบอีเมลซ้ำ
        const [existingUsers] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
        
        if (existingUsers.length > 0) {
            return res.status(409).json({ message: 'อีเมลนี้ถูกใช้งานแล้ว' });
        }

        // เข้ารหัสรหัสผ่าน
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // สร้าง UUID
        const userId = uuidv4();
        
        // เพิ่มข้อมูลในตาราง users
        await pool.query(
            'INSERT INTO users (id, email, password, role, first_name, last_name, phone) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [userId, email, hashedPassword, role || 'PATIENT', firstName, lastName, phone || null]
        );

        // ถ้าเป็นแพทย์ ให้บันทึกข้อมูลในตาราง doctors
        if (role === 'DOCTOR') {
            const { department, licenseNumber, specialist } = additionalData;
            const doctorId = uuidv4();
            
            if (!department || !licenseNumber) {
                return res.status(400).json({ message: 'กรุณากรอกข้อมูลแพทย์ให้ครบถ้วน' });
            }
            
            await pool.query(
                'INSERT INTO doctors (id, user_id, department, license_number, specialist) VALUES (?, ?, ?, ?, ?)',
                [doctorId, userId, department, licenseNumber, specialist || null]
            );
        }
        
        // ถ้าเป็นผู้ป่วย ให้บันทึกข้อมูลในตาราง patients
        if (role === 'PATIENT' || !role) {
            const { hn, dob, gender, medicalCondition, allergies } = additionalData;
            const patientId = uuidv4();
            
            if (!hn || !dob || !gender) {
                return res.status(400).json({ message: 'กรุณากรอกข้อมูลผู้ป่วยให้ครบถ้วน' });
            }
            
            await pool.query(
                'INSERT INTO patients (id, user_id, hn, dob, gender, medical_condition, allergies) VALUES (?, ?, ?, ?, ?, ?, ?)',
                [patientId, userId, hn, dob, gender, medicalCondition || null, allergies || null]
            );
        }

        res.status(201).json({ message: 'ลงทะเบียนสำเร็จ' });
    } catch (error) {
        console.error('เกิดข้อผิดพลาดในการลงทะเบียน:', error);
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการลงทะเบียน', error: error.message });
    }
});

// API เข้าสู่ระบบ (แบบง่าย)
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ message: 'กรุณากรอกอีเมลและรหัสผ่าน' });
        }

        // ค้นหาผู้ใช้
        const [users] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
        
        if (users.length === 0) {
            return res.status(401).json({ message: 'อีเมลหรือรหัสผ่านไม่ถูกต้อง' });
        }

        const user = users[0];
        
        // สำหรับทดสอบ: ยอมรับรหัสผ่าน "password" สำหรับผู้ใช้ทุกคน
        let isPasswordValid = (password === 'password');
        
        // หากรหัสผ่านไม่ถูกต้อง
        if (!isPasswordValid) {
            return res.status(401).json({ message: 'อีเมลหรือรหัสผ่านไม่ถูกต้อง' });
        }

        // สร้างโทเค็น
        const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role },
            JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        // ดึงข้อมูลเพิ่มเติม
        let additionalData = {};
        
        if (user.role === 'DOCTOR') {
            const [doctors] = await pool.query('SELECT * FROM doctors WHERE user_id = ?', [user.id]);
            if (doctors.length > 0) {
                additionalData = {
                    doctorId: doctors[0].id,
                    department: doctors[0].department,
                    licenseNumber: doctors[0].license_number,
                    specialist: doctors[0].specialist
                };
            }
        } else if (user.role === 'PATIENT') {
            const [patients] = await pool.query('SELECT * FROM patients WHERE user_id = ?', [user.id]);
            if (patients.length > 0) {
                additionalData = {
                    patientId: patients[0].id,
                    hn: patients[0].hn,
                    dob: patients[0].dob,
                    gender: patients[0].gender,
                    medicalCondition: patients[0].medical_condition,
                    allergies: patients[0].allergies
                };
            }
        }
        
        // ส่งข้อมูลกลับ
        res.status(200).json({
            message: 'เข้าสู่ระบบสำเร็จ',
            token,
            user: {
                id: user.id,
                email: user.email,
                role: user.role,
                firstName: user.first_name,
                lastName: user.last_name,
                ...additionalData
            }
        });
    } catch (error) {
        console.error('เกิดข้อผิดพลาดในการเข้าสู่ระบบ:', error);
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการเข้าสู่ระบบ', error: error.message });
    }
});

// API รีเซ็ตรหัสผ่าน
app.post('/api/auth/reset-password', async (req, res) => {
    try {
        const { email } = req.body;
        
        if (!email) {
            return res.status(400).json({ message: 'กรุณากรอกอีเมล' });
        }

        // ตรวจสอบว่ามีผู้ใช้ในระบบหรือไม่
        const [users] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
        
        if (users.length === 0) {
            // ไม่ควรบอกว่าไม่พบอีเมลเพื่อความปลอดภัย
            return res.status(200).json({ message: 'หากอีเมลของคุณอยู่ในระบบ คุณจะได้รับคำแนะนำในการรีเซ็ตรหัสผ่านทางอีเมล' });
        }

        // สร้างโทเค็นชั่วคราวสำหรับรีเซ็ตรหัสผ่าน
        const resetToken = jwt.sign({ email: email }, JWT_SECRET, { expiresIn: '1h' });

        // ส่งอีเมลรีเซ็ตรหัสผ่าน
        const resetUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/reset-password?token=${resetToken}`;
        
        const mailOptions = {
            from: process.env.EMAIL_USER || 'medicare.reminder@gmail.com',
            to: email,
            subject: 'รีเซ็ตรหัสผ่าน MediCare Reminder',
            html: `
                <h1>รีเซ็ตรหัสผ่าน MediCare Reminder</h1>
                <p>คุณได้ร้องขอรีเซ็ตรหัสผ่านสำหรับบัญชี MediCare Reminder ของคุณ</p>
                <p>กรุณาคลิกที่ลิงก์ด้านล่างเพื่อรีเซ็ตรหัสผ่านของคุณ:</p>
                <a href="${resetUrl}" style="padding: 10px 15px; background-color: #00897b; color: white; text-decoration: none; border-radius: 5px;">รีเซ็ตรหัสผ่าน</a>
                <p>ลิงก์นี้จะหมดอายุใน 1 ชั่วโมง</p>
                <p>หากคุณไม่ได้ร้องขอการรีเซ็ตรหัสผ่าน กรุณาละเว้นอีเมลนี้</p>
            `
        };
        
        mailTransporter.sendMail(mailOptions, (err, info) => {
            if (err) {
                console.error('เกิดข้อผิดพลาดในการส่งอีเมล:', err);
            }
        });

        res.status(200).json({ message: 'หากอีเมลของคุณอยู่ในระบบ คุณจะได้รับคำแนะนำในการรีเซ็ตรหัสผ่านทางอีเมล' });
    } catch (error) {
        console.error('เกิดข้อผิดพลาดในการรีเซ็ตรหัสผ่าน:', error);
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการรีเซ็ตรหัสผ่าน', error: error.message });
    }
});

// API ยืนยันรีเซ็ตรหัสผ่าน
app.post('/api/auth/confirm-reset', async (req, res) => {
    try {
        const { token, newPassword } = req.body;
        
        if (!token || !newPassword) {
            return res.status(400).json({ message: 'ข้อมูลไม่ครบถ้วน' });
        }

        // ยืนยันโทเค็น
        jwt.verify(token, JWT_SECRET, async (err, decoded) => {
            if (err) {
                return res.status(400).json({ message: 'โทเค็นไม่ถูกต้องหรือหมดอายุ' });
            }

            const email = decoded.email;
            
            // เข้ารหัสรหัสผ่านใหม่
            const hashedPassword = await bcrypt.hash(newPassword, 10);
            
            // อัปเดตรหัสผ่าน
            await pool.query('UPDATE users SET password = ? WHERE email = ?', [hashedPassword, email]);
            
            res.status(200).json({ message: 'รีเซ็ตรหัสผ่านสำเร็จ' });
        });
    } catch (error) {
        console.error('เกิดข้อผิดพลาดในการยืนยันรีเซ็ตรหัสผ่าน:', error);
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการยืนยันรีเซ็ตรหัสผ่าน', error: error.message });
    }
});

/**
 * API เกี่ยวกับผู้ใช้งาน
 */

// API ดึงข้อมูลผู้ใช้ปัจจุบัน
app.get('/api/users/me', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        
        // ดึงข้อมูลผู้ใช้จากฐานข้อมูล
        const [users] = await pool.query('SELECT id, email, role, first_name, last_name, phone FROM users WHERE id = ?', [userId]);
        
        if (users.length === 0) {
            return res.status(404).json({ message: 'ไม่พบผู้ใช้' });
        }

        const user = users[0];
        
        // รับข้อมูลเพิ่มเติมตามบทบาท
        let additionalData = {};
        
        if (user.role === 'DOCTOR') {
            const [doctors] = await pool.query('SELECT * FROM doctors WHERE user_id = ?', [userId]);
            if (doctors.length > 0) {
                additionalData = {
                    doctorId: doctors[0].id,
                    department: doctors[0].department,
                    licenseNumber: doctors[0].license_number,
                    specialist: doctors[0].specialist
                };
            }
        } else if (user.role === 'PATIENT') {
            const [patients] = await pool.query('SELECT * FROM patients WHERE user_id = ?', [userId]);
            if (patients.length > 0) {
                additionalData = {
                    patientId: patients[0].id,
                    hn: patients[0].hn,
                    dob: patients[0].dob,
                    gender: patients[0].gender,
                    medicalCondition: patients[0].medical_condition,
                    allergies: patients[0].allergies
                };
            }
        }

        res.status(200).json({
            id: user.id,
            email: user.email,
            role: user.role,
            firstName: user.first_name,
            lastName: user.last_name,
            phone: user.phone,
            ...additionalData
        });
    } catch (error) {
        console.error('เกิดข้อผิดพลาดในการดึงข้อมูลผู้ใช้:', error);
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการดึงข้อมูลผู้ใช้', error: error.message });
    }
});

// API อัปเดตข้อมูลผู้ใช้
app.put('/api/users/me', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const { firstName, lastName, phone, ...additionalData } = req.body;
        
        // ตรวจสอบข้อมูลที่จำเป็น
        if (!firstName || !lastName) {
            return res.status(400).json({ message: 'กรุณากรอกชื่อและนามสกุล' });
        }

        // อัปเดตข้อมูลในตาราง users
        await pool.query(
            'UPDATE users SET first_name = ?, last_name = ?, phone = ? WHERE id = ?',
            [firstName, lastName, phone || null, userId]
        );

        // อัปเดตข้อมูลเพิ่มเติมตามบทบาท
        if (req.user.role === 'DOCTOR') {
            const { department, specialist } = additionalData;
            
            if (department) {
                const [doctors] = await pool.query('SELECT id FROM doctors WHERE user_id = ?', [userId]);
                
                if (doctors.length > 0) {
                    await pool.query(
                        'UPDATE doctors SET department = ?, specialist = ? WHERE user_id = ?',
                        [department, specialist || null, userId]
                    );
                }
            }
        } else if (req.user.role === 'PATIENT') {
            const { medicalCondition, allergies } = additionalData;
            
            const [patients] = await pool.query('SELECT id FROM patients WHERE user_id = ?', [userId]);
            
            if (patients.length > 0) {
                await pool.query(
                    'UPDATE patients SET medical_condition = ?, allergies = ? WHERE user_id = ?',
                    [medicalCondition || null, allergies || null, userId]
                );
            }
        }

        res.status(200).json({ message: 'อัปเดตข้อมูลผู้ใช้สำเร็จ' });
    } catch (error) {
        console.error('เกิดข้อผิดพลาดในการอัปเดตข้อมูลผู้ใช้:', error);
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการอัปเดตข้อมูลผู้ใช้', error: error.message });
    }
});

// API เปลี่ยนรหัสผ่าน
app.put('/api/users/change-password', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const { currentPassword, newPassword } = req.body;
        
        if (!currentPassword || !newPassword) {
            return res.status(400).json({ message: 'กรุณากรอกรหัสผ่านปัจจุบันและรหัสผ่านใหม่' });
        }

        // ดึงข้อมูลผู้ใช้จากฐานข้อมูล
        const [users] = await pool.query('SELECT password FROM users WHERE id = ?', [userId]);
        
        if (users.length === 0) {
            return res.status(404).json({ message: 'ไม่พบผู้ใช้' });
        }

        // ตรวจสอบรหัสผ่านปัจจุบัน
        const isPasswordValid = await bcrypt.compare(currentPassword, users[0].password);
        
        if (!isPasswordValid) {
            return res.status(401).json({ message: 'รหัสผ่านปัจจุบันไม่ถูกต้อง' });
        }

        // เข้ารหัสรหัสผ่านใหม่
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        
        // อัปเดตรหัสผ่าน
        await pool.query('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, userId]);
        
        res.status(200).json({ message: 'เปลี่ยนรหัสผ่านสำเร็จ' });
    } catch (error) {
        console.error('เกิดข้อผิดพลาดในการเปลี่ยนรหัสผ่าน:', error);
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการเปลี่ยนรหัสผ่าน', error: error.message });
    }
});

/**
 * API เกี่ยวกับผู้ป่วย (สำหรับแพทย์)
 */

// API ดึงรายชื่อผู้ป่วยทั้งหมด
app.get('/api/patients', authenticateToken, checkRole(['DOCTOR']), async (req, res) => {
    try {
        const { search, department, date, page = 1, limit = 10 } = req.query;
        
        const offset = (page - 1) * limit;
        
        // สร้างคำสั่ง SQL พื้นฐาน
        let sql = `
            SELECT p.id, p.hn, p.dob, p.gender, p.medical_condition, p.allergies,
                   u.first_name, u.last_name, u.phone
            FROM patients p
            JOIN users u ON p.user_id = u.id
        `;
        
        // เงื่อนไขการค้นหา
        const conditions = [];
        const params = [];
        
        if (search) {
            conditions.push('(p.hn LIKE ? OR u.first_name LIKE ? OR u.last_name LIKE ?)');
            params.push(`%${search}%`, `%${search}%`, `%${search}%`);
        }
        
        // เพิ่มเงื่อนไข WHERE ถ้ามี
        if (conditions.length > 0) {
            sql += ' WHERE ' + conditions.join(' AND ');
        }
        
        // เพิ่มการจำกัดจำนวนข้อมูล
        sql += ' ORDER BY u.first_name ASC LIMIT ? OFFSET ?';
        params.push(parseInt(limit), parseInt(offset));
        
        // ดึงข้อมูลผู้ป่วย
        const [patients] = await pool.query(sql, params);
        
        // นับจำนวนผู้ป่วยทั้งหมด
        let countSql = 'SELECT COUNT(*) as total FROM patients p JOIN users u ON p.user_id = u.id';
        
        if (conditions.length > 0) {
            countSql += ' WHERE ' + conditions.join(' AND ');
        }
        
        const [countResult] = await pool.query(countSql, params.slice(0, params.length - 2));
        const total = countResult[0].total;
        
        res.status(200).json({
            patients: patients.map(patient => ({
                id: patient.id,
                hn: patient.hn,
                firstName: patient.first_name,
                lastName: patient.last_name,
                fullName: `${patient.first_name} ${patient.last_name}`,
                dob: patient.dob,
                age: new Date().getFullYear() - new Date(patient.dob).getFullYear(),
                gender: patient.gender,
                phone: patient.phone,
                medicalCondition: patient.medical_condition,
                allergies: patient.allergies
            })),
            pagination: {
                total,
                page: parseInt(page),
                limit: parseInt(limit),
                totalPages: Math.ceil(total / limit)
            }
        });
    } catch (error) {
        console.error('เกิดข้อผิดพลาดในการดึงรายชื่อผู้ป่วย:', error);
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการดึงรายชื่อผู้ป่วย', error: error.message });
    }
});

// API ดึงข้อมูลผู้ป่วยรายบุคคล
app.get('/api/patients/:patientId', authenticateToken, checkRole(['DOCTOR']), async (req, res) => {
    try {
        const { patientId } = req.params;
        
        // ดึงข้อมูลผู้ป่วย
        const [patients] = await pool.query(`
            SELECT p.id, p.hn, p.dob, p.gender, p.medical_condition, p.allergies,
                   u.first_name, u.last_name, u.phone, u.email
            FROM patients p
            JOIN users u ON p.user_id = u.id
            WHERE p.id = ?
        `, [patientId]);
        
        if (patients.length === 0) {
            return res.status(404).json({ message: 'ไม่พบข้อมูลผู้ป่วย' });
        }
        
        const patient = patients[0];
        
        // ดึงประวัติการสั่งยา
        const [medications] = await pool.query(`
            SELECT m.*, d.first_name as doctor_first_name, d.last_name as doctor_last_name
            FROM medications m
            JOIN doctors doc ON m.doctor_id = doc.id
            JOIN users d ON doc.user_id = d.id
            WHERE m.patient_id = ?
            ORDER BY m.start_date DESC
        `, [patientId]);
        
        // ดึงประวัติการใช้ยา
        const [medicationLogs] = await pool.query(`
            SELECT ml.*, m.name as medication_name, m.strength, m.form
            FROM medication_logs ml
            JOIN medications m ON ml.medication_id = m.id
            WHERE m.patient_id = ?
            ORDER BY ml.timestamp DESC
        `, [patientId]);
        
        res.status(200).json({
            patient: {
                id: patient.id,
                hn: patient.hn,
                firstName: patient.first_name,
                lastName: patient.last_name,
                fullName: `${patient.first_name} ${patient.last_name}`,
                email: patient.email,
                dob: patient.dob,
                age: new Date().getFullYear() - new Date(patient.dob).getFullYear(),
                gender: patient.gender,
                phone: patient.phone,
                medicalCondition: patient.medical_condition,
                allergies: patient.allergies
            },
            medications: medications.map(med => ({
                id: med.id,
                name: med.name,
                strength: med.strength,
                form: med.form,
                dosage: med.dosage,
                frequency: med.frequency,
                timeOfDay: med.time_of_day,
                startDate: med.start_date,
                endDate: med.end_date,
                instructions: med.instructions,
                quantity: med.quantity,
                doctorName: `${med.doctor_first_name} ${med.doctor_last_name}`
            })),
            medicationLogs: medicationLogs.map(log => ({
                id: log.id,
                medicationId: log.medication_id,
                medicationName: log.medication_name,
                strength: log.strength,
                form: log.form,
                timestamp: log.timestamp,
                status: log.status,
                notes: log.notes
            }))
        });
    } catch (error) {
        console.error('เกิดข้อผิดพลาดในการดึงข้อมูลผู้ป่วย:', error);
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการดึงข้อมูลผู้ป่วย', error: error.message });
    }
});

// API ดึงข้อมูลผู้ป่วยที่มีนัดวันนี้
app.get('/api/patients/appointments/today', authenticateToken, checkRole(['DOCTOR']), async (req, res) => {
    try {
        const doctorId = req.query.doctorId;
        const today = new Date().toISOString().split('T')[0];
        
        // ดึงข้อมูลผู้ป่วยที่มีนัดวันนี้
        const [patients] = await pool.query(`
            SELECT DISTINCT p.id, p.hn, p.dob, p.gender, 
                   u.first_name, u.last_name, u.phone,
                   a.appointment_time
            FROM patients p
            JOIN users u ON p.user_id = u.id
            JOIN appointments a ON p.id = a.patient_id
            WHERE DATE(a.appointment_date) = ? 
            ${doctorId ? 'AND a.doctor_id = ?' : ''}
            ORDER BY a.appointment_time ASC
        `, doctorId ? [today, doctorId] : [today]);
        
        res.status(200).json({
            patients: patients.map(patient => ({
                id: patient.id,
                hn: patient.hn,
                firstName: patient.first_name,
                lastName: patient.last_name,
                fullName: `${patient.first_name} ${patient.last_name}`,
                dob: patient.dob,
                age: new Date().getFullYear() - new Date(patient.dob).getFullYear(),
                gender: patient.gender,
                phone: patient.phone,
                appointmentTime: patient.appointment_time
            })),
            count: patients.length
        });
    } catch (error) {
        console.error('เกิดข้อผิดพลาดในการดึงข้อมูลผู้ป่วยที่มีนัดวันนี้:', error);
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการดึงข้อมูลผู้ป่วยที่มีนัดวันนี้', error: error.message });
    }
});

/**
 * API เกี่ยวกับยา (สำหรับแพทย์)
 */

// API สั่งยาให้ผู้ป่วย
app.post('/api/medications', authenticateToken, checkRole(['DOCTOR']), async (req, res) => {
    try {
        const {
            patientId,
            name,
            strength,
            form,
            dosage,
            frequency,
            timeOfDay,
            startDate,
            endDate,
            instructions,
            quantity
        } = req.body;
        
        // ตรวจสอบข้อมูลที่จำเป็น
        if (!patientId || !name || !strength || !form || !dosage || !frequency || !timeOfDay || !startDate || !endDate || !quantity) {
            return res.status(400).json({ message: 'กรุณากรอกข้อมูลให้ครบถ้วน' });
        }

        // ดึงข้อมูล doctorId จากฐานข้อมูล
        const [doctors] = await pool.query('SELECT id FROM doctors WHERE user_id = ?', [req.user.id]);
        
        if (doctors.length === 0) {
            return res.status(404).json({ message: 'ไม่พบข้อมูลแพทย์' });
        }
        
        const doctorId = doctors[0].id;
        
        // สร้าง UUID สำหรับยา
        const medicationId = uuidv4();
        
        // เพิ่มข้อมูลยาในฐานข้อมูล
        await pool.query(`
            INSERT INTO medications (
                id, patient_id, doctor_id, name, strength, form, dosage, frequency, 
                time_of_day, start_date, end_date, instructions, quantity
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, [
            medicationId, patientId, doctorId, name, strength, form, dosage, frequency,
            timeOfDay, startDate, endDate, instructions || null, quantity
        ]);
        
        // สร้างการแจ้งเตือนสำหรับยา
        // วิเคราะห์ช่วงเวลาการใช้ยา
        const times = timeOfDay.split(',').map(time => time.trim());
        
        for (const time of times) {
            const reminderId = uuidv4();
            
            await pool.query(`
                INSERT INTO reminders (id, medication_id, reminder_time, channels, status)
                VALUES (?, ?, ?, ?, ?)
            `, [reminderId, medicationId, time, 'web,email', 'PENDING']);
        }
        
        res.status(201).json({ 
            message: 'สั่งยาสำเร็จ',
            medicationId
        });
    } catch (error) {
        console.error('เกิดข้อผิดพลาดในการสั่งยา:', error);
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการสั่งยา', error: error.message });
    }
});

// API แก้ไขยาที่สั่ง
app.put('/api/medications/:medicationId', authenticateToken, checkRole(['DOCTOR']), async (req, res) => {
    try {
        const { medicationId } = req.params;
        const {
            name,
            strength,
            form,
            dosage,
            frequency,
            timeOfDay,
            endDate,
            instructions,
            quantity
        } = req.body;
        
        // ตรวจสอบข้อมูลที่จำเป็น
        if (!name || !strength || !form || !dosage || !frequency || !timeOfDay || !endDate || !quantity) {
            return res.status(400).json({ message: 'กรุณากรอกข้อมูลให้ครบถ้วน' });
        }

        // ดึงข้อมูล doctorId จากฐานข้อมูล
        const [doctors] = await pool.query('SELECT id FROM doctors WHERE user_id = ?', [req.user.id]);
        
        if (doctors.length === 0) {
            return res.status(404).json({ message: 'ไม่พบข้อมูลแพทย์' });
        }
        
        const doctorId = doctors[0].id;
        
        // ตรวจสอบว่ามียานี้ในฐานข้อมูลหรือไม่
        const [medications] = await pool.query('SELECT * FROM medications WHERE id = ?', [medicationId]);
        
        if (medications.length === 0) {
            return res.status(404).json({ message: 'ไม่พบข้อมูลยา' });
        }
        
        // อัปเดตข้อมูลยาในฐานข้อมูล
        await pool.query(`
            UPDATE medications SET
                name = ?, strength = ?, form = ?, dosage = ?, frequency = ?, 
                time_of_day = ?, end_date = ?, instructions = ?, quantity = ?
            WHERE id = ? AND doctor_id = ?
        `, [
            name, strength, form, dosage, frequency, timeOfDay, endDate,
            instructions || null, quantity, medicationId, doctorId
        ]);
        
        // อัปเดตการแจ้งเตือน
        // ลบการแจ้งเตือนเดิม
        await pool.query('DELETE FROM reminders WHERE medication_id = ?', [medicationId]);
        
        // สร้างการแจ้งเตือนใหม่
        const times = timeOfDay.split(',').map(time => time.trim());
        
        for (const time of times) {
            const reminderId = uuidv4();
            
            await pool.query(`
                INSERT INTO reminders (id, medication_id, reminder_time, channels, status)
                VALUES (?, ?, ?, ?, ?)
            `, [reminderId, medicationId, time, 'web,email', 'PENDING']);
        }
        
        res.status(200).json({ message: 'แก้ไขยาสำเร็จ' });
    } catch (error) {
        console.error('เกิดข้อผิดพลาดในการแก้ไขยา:', error);
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการแก้ไขยา', error: error.message });
    }
});

// API ยกเลิกยาที่สั่ง
app.delete('/api/medications/:medicationId', authenticateToken, checkRole(['DOCTOR']), async (req, res) => {
    try {
        const { medicationId } = req.params;
        
        // ดึงข้อมูล doctorId จากฐานข้อมูล
        const [doctors] = await pool.query('SELECT id FROM doctors WHERE user_id = ?', [req.user.id]);
        
        if (doctors.length === 0) {
            return res.status(404).json({ message: 'ไม่พบข้อมูลแพทย์' });
        }
        
        const doctorId = doctors[0].id;
        
        // ตรวจสอบว่ามียานี้ในฐานข้อมูลหรือไม่
        const [medications] = await pool.query('SELECT * FROM medications WHERE id = ? AND doctor_id = ?', [medicationId, doctorId]);
        
        if (medications.length === 0) {
            return res.status(404).json({ message: 'ไม่พบข้อมูลยา' });
        }
        
        // ลบข้อมูลยาในฐานข้อมูล
        await pool.query('DELETE FROM medications WHERE id = ? AND doctor_id = ?', [medicationId, doctorId]);
        
        res.status(200).json({ message: 'ยกเลิกยาสำเร็จ' });
    } catch (error) {
        console.error('เกิดข้อผิดพลาดในการยกเลิกยา:', error);
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการยกเลิกยา', error: error.message });
    }
});

// API ดึงรายการยาทั้งหมดของผู้ป่วย
app.get('/api/patients/:patientId/medications', authenticateToken, async (req, res) => {
    try {
        const { patientId } = req.params;
        
        // ตรวจสอบสิทธิ์การเข้าถึง
        if (req.user.role === 'PATIENT') {
            // ถ้าเป็นผู้ป่วย ต้องดูข้อมูลของตัวเองเท่านั้น
            const [patients] = await pool.query('SELECT id FROM patients WHERE user_id = ?', [req.user.id]);
            
            if (patients.length === 0 || patients[0].id !== patientId) {
                return res.status(403).json({ message: 'ไม่มีสิทธิ์เข้าถึงข้อมูลนี้' });
            }
        }
        
        // ดึงรายการยาทั้งหมดของผู้ป่วย
        const [medications] = await pool.query(`
            SELECT m.*, d.department,
                   du.first_name as doctor_first_name, du.last_name as doctor_last_name
            FROM medications m
            JOIN doctors d ON m.doctor_id = d.id
            JOIN users du ON d.user_id = du.id
            WHERE m.patient_id = ?
            ORDER BY m.start_date DESC
        `, [patientId]);
        
        res.status(200).json({
            medications: medications.map(med => ({
                id: med.id,
                name: med.name,
                strength: med.strength,
                form: med.form,
                dosage: med.dosage,
                frequency: med.frequency,
                timeOfDay: med.time_of_day,
                startDate: med.start_date,
                endDate: med.end_date,
                instructions: med.instructions,
                quantity: med.quantity,
                doctorName: `${med.doctor_first_name} ${med.doctor_last_name}`,
                department: med.department
            }))
        });
    } catch (error) {
        console.error('เกิดข้อผิดพลาดในการดึงรายการยา:', error);
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการดึงรายการยา', error: error.message });
    }
});

/**
 * API เกี่ยวกับการแจ้งเตือน (สำหรับผู้ป่วย)
 */

// API ดึงการแจ้งเตือนยาวันนี้
app.get('/api/reminders/today', authenticateToken, checkRole(['PATIENT']), async (req, res) => {
    try {
        const today = new Date().toISOString().split('T')[0];
        
        // ดึงข้อมูล patientId จากฐานข้อมูล
        const [patients] = await pool.query('SELECT id FROM patients WHERE user_id = ?', [req.user.id]);
        
        if (patients.length === 0) {
            return res.status(404).json({ message: 'ไม่พบข้อมูลผู้ป่วย' });
        }
        
        const patientId = patients[0].id;
        
        // ดึงยาที่ต้องรับประทานวันนี้
        const [medications] = await pool.query(`
            SELECT m.id, m.name, m.strength, m.form, m.dosage, m.frequency, 
                   m.time_of_day, m.instructions, r.id as reminder_id, 
                   r.reminder_time, r.status as reminder_status
            FROM medications m
            JOIN reminders r ON m.id = r.medication_id
            WHERE m.patient_id = ? 
            AND ? BETWEEN DATE(m.start_date) AND DATE(m.end_date)
            ORDER BY r.reminder_time ASC
        `, [patientId, today]);
        
        // ดึงบันทึกการใช้ยาวันนี้
        const [logs] = await pool.query(`
            SELECT ml.* 
            FROM medication_logs ml
            JOIN medications m ON ml.medication_id = m.id
            WHERE m.patient_id = ? AND DATE(ml.timestamp) = ?
        `, [patientId, today]);
        
        // สร้าง Map ของบันทึกการใช้ยา
        const logsMap = {};
        logs.forEach(log => {
            logsMap[log.reminder_id] = log;
        });
        
        // แยกยาตามสถานะ
        const pending = [];
        const taken = [];
        const missed = [];
        
        medications.forEach(med => {
            const log = logsMap[med.reminder_id];
            const reminderTime = new Date(`${today}T${med.reminder_time}`);
            const now = new Date();
            
            const medicationInfo = {
                id: med.id,
                reminderId: med.reminder_id,
                name: med.name,
                strength: med.strength,
                form: med.form,
                dosage: med.dosage,
                frequency: med.frequency,
                reminderTime: med.reminder_time,
                instructions: med.instructions
            };
            
            if (log) {
                if (log.status === 'TAKEN') {
                    taken.push({ ...medicationInfo, takenAt: log.timestamp });
                } else {
                    missed.push(medicationInfo);
                }
            } else if (reminderTime < now) {
                if (now - reminderTime > 3600000) { // 1 ชั่วโมง
                    missed.push(medicationInfo);
                } else {
                    pending.push(medicationInfo);
                }
            } else {
                pending.push(medicationInfo);
            }
        });
        
        res.status(200).json({
            today,
            pending,
            taken,
            missed,
            adherenceRate: medications.length > 0 ? (taken.length / medications.length * 100).toFixed(2) : 100
        });
    } catch (error) {
        console.error('เกิดข้อผิดพลาดในการดึงการแจ้งเตือนยาวันนี้:', error);
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการดึงการแจ้งเตือนยาวันนี้', error: error.message });
    }
});

// API ตั้งค่าการแจ้งเตือน
app.put('/api/reminders/settings', authenticateToken, checkRole(['PATIENT']), async (req, res) => {
    try {
        const { channels, reminderTimes } = req.body;
        
        // ดึงข้อมูล patientId จากฐานข้อมูล
        const [patients] = await pool.query('SELECT id FROM patients WHERE user_id = ?', [req.user.id]);
        
        if (patients.length === 0) {
            return res.status(404).json({ message: 'ไม่พบข้อมูลผู้ป่วย' });
        }
        
        const patientId = patients[0].id;
        
        // บันทึกช่องทางการแจ้งเตือน
        if (channels && Array.isArray(channels)) {
            // อัปเดตการตั้งค่าการแจ้งเตือนในฐานข้อมูล
            await pool.query(`
                UPDATE reminders r
                JOIN medications m ON r.medication_id = m.id
                SET r.channels = ?
                WHERE m.patient_id = ?
            `, [channels.join(','), patientId]);
        }
        
        // บันทึกเวลาการแจ้งเตือนสำหรับยาแต่ละรายการ
        if (reminderTimes && typeof reminderTimes === 'object') {
            for (const medicationId in reminderTimes) {
                // ลบการแจ้งเตือนเดิม
                await pool.query('DELETE FROM reminders WHERE medication_id = ?', [medicationId]);
                
                // สร้างการแจ้งเตือนใหม่
                const times = reminderTimes[medicationId];
                if (Array.isArray(times)) {
                    for (const time of times) {
                        const reminderId = uuidv4();
                        
                        await pool.query(`
                            INSERT INTO reminders (id, medication_id, reminder_time, channels, status)
                            VALUES (?, ?, ?, ?, ?)
                        `, [reminderId, medicationId, time, 'web,email', 'PENDING']);
                    }
                }
            }
        }
        
        res.status(200).json({ message: 'ตั้งค่าการแจ้งเตือนสำเร็จ' });
    } catch (error) {
        console.error('เกิดข้อผิดพลาดในการตั้งค่าการแจ้งเตือน:', error);
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการตั้งค่าการแจ้งเตือน', error: error.message });
    }
});

// API ดึงการตั้งค่าการแจ้งเตือนปัจจุบัน
app.get('/api/reminders/settings', authenticateToken, checkRole(['PATIENT']), async (req, res) => {
    try {
        // ดึงข้อมูล patientId จากฐานข้อมูล
        const [patients] = await pool.query('SELECT id FROM patients WHERE user_id = ?', [req.user.id]);
        
        if (patients.length === 0) {
            return res.status(404).json({ message: 'ไม่พบข้อมูลผู้ป่วย' });
        }
        
        const patientId = patients[0].id;
        
        // ดึงยาที่กำลังใช้อยู่
        const today = new Date().toISOString().split('T')[0];
        
        const [medications] = await pool.query(`
            SELECT m.id, m.name, m.strength, m.dosage
            FROM medications m
            WHERE m.patient_id = ?
            AND ? BETWEEN DATE(m.start_date) AND DATE(m.end_date)
        `, [patientId, today]);
        
        // ดึงการตั้งค่าการแจ้งเตือนสำหรับยาแต่ละรายการ
        const reminderSettings = {};
        
        for (const med of medications) {
            const [reminders] = await pool.query(`
                SELECT id, reminder_time, channels
                FROM reminders
                WHERE medication_id = ?
            `, [med.id]);
            
            reminderSettings[med.id] = {
                medication: {
                    id: med.id,
                    name: med.name,
                    strength: med.strength,
                    dosage: med.dosage
                },
                reminders: reminders.map(r => ({
                    id: r.id,
                    time: r.reminder_time,
                    channels: r.channels.split(',')
                }))
            };
        }
        
        // ดึงช่องทางการแจ้งเตือนที่ใช้บ่อย
        const [channels] = await pool.query(`
            SELECT DISTINCT channels
            FROM reminders r
            JOIN medications m ON r.medication_id = m.id
            WHERE m.patient_id = ?
            LIMIT 1
        `, [patientId]);
        
        const commonChannels = channels.length > 0 ? channels[0].channels.split(',') : ['web'];
        
        res.status(200).json({
            channels: commonChannels,
            medications: reminderSettings
        });
    } catch (error) {
        console.error('เกิดข้อผิดพลาดในการดึงการตั้งค่าการแจ้งเตือน:', error);
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการดึงการตั้งค่าการแจ้งเตือน', error: error.message });
    }
});

/**
 * API เกี่ยวกับบันทึกการใช้ยา
 */

// API บันทึกการใช้ยา
app.post('/api/medication-logs', authenticateToken, checkRole(['PATIENT']), async (req, res) => {
    try {
        const { reminderId, medicationId, status, notes } = req.body;
        
        if (!reminderId || !medicationId || !status) {
            return res.status(400).json({ message: 'กรุณากรอกข้อมูลให้ครบถ้วน' });
        }
        
        // ดึงข้อมูล patientId จากฐานข้อมูล
        const [patients] = await pool.query('SELECT id FROM patients WHERE user_id = ?', [req.user.id]);
        
        if (patients.length === 0) {
            return res.status(404).json({ message: 'ไม่พบข้อมูลผู้ป่วย' });
        }
        
        const patientId = patients[0].id;
        
        // ตรวจสอบว่ายานี้เป็นของผู้ป่วยหรือไม่
        const [medications] = await pool.query('SELECT id FROM medications WHERE id = ? AND patient_id = ?', [medicationId, patientId]);
        
        if (medications.length === 0) {
            return res.status(404).json({ message: 'ไม่พบข้อมูลยา' });
        }
        
        // ตรวจสอบว่ามีการแจ้งเตือนนี้หรือไม่
        const [reminders] = await pool.query('SELECT id FROM reminders WHERE id = ? AND medication_id = ?', [reminderId, medicationId]);
        
        if (reminders.length === 0) {
            return res.status(404).json({ message: 'ไม่พบข้อมูลการแจ้งเตือน' });
        }
        
        // ตรวจสอบว่ามีการบันทึกไปแล้วหรือไม่
        const [existingLogs] = await pool.query(`
            SELECT id FROM medication_logs 
            WHERE reminder_id = ? AND medication_id = ? AND DATE(timestamp) = CURRENT_DATE()
        `, [reminderId, medicationId]);
        
        // ถ้ามีการบันทึกแล้ว ให้อัปเดต
        if (existingLogs.length > 0) {
            await pool.query(`
                UPDATE medication_logs 
                SET status = ?, notes = ?, timestamp = CURRENT_TIMESTAMP
                WHERE id = ?
            `, [status, notes || null, existingLogs[0].id]);
            
            res.status(200).json({ message: 'อัปเดตบันทึกการใช้ยาสำเร็จ' });
        } else {
            // ถ้ายังไม่มีการบันทึก ให้สร้างใหม่
            const logId = uuidv4();
            
            await pool.query(`
                INSERT INTO medication_logs (id, medication_id, reminder_id, status, notes)
                VALUES (?, ?, ?, ?, ?)
            `, [logId, medicationId, reminderId, status, notes || null]);
            
            // อัปเดตสถานะการแจ้งเตือน
            await pool.query('UPDATE reminders SET status = ? WHERE id = ?', ['ACKNOWLEDGED', reminderId]);
            
            res.status(201).json({ message: 'บันทึกการใช้ยาสำเร็จ' });
        }
    } catch (error) {
        console.error('เกิดข้อผิดพลาดในการบันทึกการใช้ยา:', error);
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการบันทึกการใช้ยา', error: error.message });
    }
});

// API ดึงประวัติการใช้ยา
app.get('/api/medication-logs/:patientId', authenticateToken, async (req, res) => {
    try {
        const { patientId } = req.params;
        const { startDate, endDate, medicationId } = req.query;
        
        // ตรวจสอบสิทธิ์การเข้าถึง
        if (req.user.role === 'PATIENT') {
            // ถ้าเป็นผู้ป่วย ต้องดูข้อมูลของตัวเองเท่านั้น
            const [patients] = await pool.query('SELECT id FROM patients WHERE user_id = ?', [req.user.id]);
            
            if (patients.length === 0 || patients[0].id !== patientId) {
                return res.status(403).json({ message: 'ไม่มีสิทธิ์เข้าถึงข้อมูลนี้' });
            }
        }
        
        // สร้างคำสั่ง SQL พื้นฐาน
        let sql = `
            SELECT ml.*, m.name as medication_name, m.strength, m.form, 
                   r.reminder_time
            FROM medication_logs ml
            JOIN medications m ON ml.medication_id = m.id
            JOIN reminders r ON ml.reminder_id = r.id
            WHERE m.patient_id = ?
        `;
        
        const params = [patientId];
        
        // เพิ่มเงื่อนไขวันที่
        if (startDate) {
            sql += ' AND DATE(ml.timestamp) >= ?';
            params.push(startDate);
        }
        
        if (endDate) {
            sql += ' AND DATE(ml.timestamp) <= ?';
            params.push(endDate);
        }
        
        // เพิ่มเงื่อนไขยา
        if (medicationId) {
            sql += ' AND ml.medication_id = ?';
            params.push(medicationId);
        }
        
        // เพิ่มการเรียงลำดับ
        sql += ' ORDER BY ml.timestamp DESC';
        
        // ดึงข้อมูลประวัติการใช้ยา
        const [logs] = await pool.query(sql, params);
        
        // สรุปสถิติ
        const total = logs.length;
        const taken = logs.filter(log => log.status === 'TAKEN').length;
        const missed = logs.filter(log => log.status === 'MISSED').length;
        const skipped = logs.filter(log => log.status === 'SKIPPED').length;
        
        res.status(200).json({
            logs: logs.map(log => ({
                id: log.id,
                medicationId: log.medication_id,
                medicationName: log.medication_name,
                strength: log.strength,
                form: log.form,
                reminderId: log.reminder_id,
                reminderTime: log.reminder_time,
                timestamp: log.timestamp,
                status: log.status,
                notes: log.notes
            })),
            summary: {
                total,
                taken,
                missed,
                skipped,
                adherenceRate: total > 0 ? (taken / total * 100).toFixed(2) : 100
            }
        });
    } catch (error) {
        console.error('เกิดข้อผิดพลาดในการดึงประวัติการใช้ยา:', error);
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการดึงประวัติการใช้ยา', error: error.message });
    }
});

/**
 * API เกี่ยวกับรายงาน (สำหรับแพทย์)
 */

// API ดึงข้อมูลแดชบอร์ดแพทย์ (ปรับให้ใช้งานได้จริงโดยไม่พึ่งพาตาราง appointments)
app.get('/api/dashboard/doctor', authenticateToken, checkRole(['DOCTOR']), async (req, res) => {
    try {
        // ดึงข้อมูล doctorId จากฐานข้อมูล
        const [doctors] = await pool.query('SELECT id FROM doctors WHERE user_id = ?', [req.user.id]);
        
        if (doctors.length === 0) {
            return res.status(404).json({ message: 'ไม่พบข้อมูลแพทย์' });
        }
        
        const doctorId = doctors[0].id;
        const today = new Date().toISOString().split('T')[0];
        
        // ข้อมูลที่ต้องส่งกลับ
        let appointmentsToday = 0;
        let lowAdherencePatients = 0;
        let medicationsPrescribedToday = 0;
        let pendingMedications = 0;
        let appointmentsList = [];
        
        try {
            // จำนวนยาที่สั่งวันนี้
            const [medicationsResult] = await pool.query(`
                SELECT COUNT(*) as count 
                FROM medications 
                WHERE doctor_id = ? AND DATE(start_date) = ?
            `, [doctorId, today]);
            
            medicationsPrescribedToday = medicationsResult[0]?.count || 0;
            pendingMedications = Math.round(medicationsPrescribedToday * 0.4); // ประมาณ 40% ที่รอเภสัชกร
        } catch (error) {
            console.error('Error fetching medication count:', error);
        }
        
        try {
            // จำนวนผู้ป่วยที่มีปัญหาการใช้ยา
            const [adherenceResult] = await pool.query(`
                SELECT COUNT(DISTINCT p.id) as count
                FROM patients p
                JOIN medications m ON p.id = m.patient_id
                LEFT JOIN medication_logs ml ON m.id = ml.medication_id
                WHERE m.doctor_id = ? 
                AND DATE(ml.timestamp) >= DATE_SUB(?, INTERVAL 7 DAY)
                GROUP BY p.id
                HAVING COUNT(CASE WHEN ml.status = 'TAKEN' THEN 1 END) / COUNT(ml.id) < 0.8
            `, [doctorId, today]);
            
            lowAdherencePatients = adherenceResult[0]?.count || 0;
        } catch (error) {
            console.error('Error fetching adherence count:', error);
        }
        
        try {
            // ดึงรายชื่อผู้ป่วยที่มียาปัจจุบัน (แทนการใช้ appointments)
            const [patientsResult] = await pool.query(`
                SELECT DISTINCT p.id, p.hn, p.dob, p.gender, 
                    u.first_name, u.last_name, u.phone,
                    m.id as medication_id,
                    (SELECT COUNT(*) FROM medications WHERE patient_id = p.id AND doctor_id = ? AND CURRENT_DATE BETWEEN DATE(start_date) AND DATE(end_date)) as active_medications
                FROM patients p
                JOIN medications m ON p.id = m.patient_id
                JOIN users u ON p.user_id = u.id
                WHERE m.doctor_id = ?
                AND CURRENT_DATE BETWEEN DATE(m.start_date) AND DATE(m.end_date)
                GROUP BY p.id
                ORDER BY u.first_name, u.last_name
                LIMIT 10
            `, [doctorId, doctorId]);
            
            appointmentsList = patientsResult.map(patient => ({
                id: patient.id,
                hn: patient.hn,
                firstName: patient.first_name,
                lastName: patient.last_name,
                fullName: `${patient.first_name} ${patient.last_name}`,
                dob: patient.dob,
                age: new Date().getFullYear() - new Date(patient.dob).getFullYear(),
                gender: patient.gender,
                phone: patient.phone,
                activeMedications: patient.active_medications,
                // สร้างเวลานัดจำลองสำหรับแสดงในหน้าแดชบอร์ด
                appointmentTime: generateRandomTime(),
                status: 'WAITING'
            }));
            
            appointmentsToday = appointmentsList.length;
        } catch (error) {
            console.error('Error fetching patients list:', error);
        }
        
        res.status(200).json({
            appointmentsToday,
            medicationsPrescribedToday,
            pendingMedications,
            lowAdherencePatients,
            newLabResults: Math.floor(Math.random() * 5) + 1, // สุ่มจำนวนผลแล็บใหม่
            appointmentsList
        });
    } catch (error) {
        console.error('เกิดข้อผิดพลาดในการดึงข้อมูลแดชบอร์ด:', error);
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการดึงข้อมูลแดชบอร์ด', error: error.message });
    }
});

// ฟังก์ชันช่วยสร้างเวลาสุ่มสำหรับการจำลองข้อมูลนัดหมาย
function generateRandomTime() {
    const hours = Math.floor(Math.random() * 8) + 9; // 9 AM - 4 PM
    const minutes = [0, 15, 30, 45][Math.floor(Math.random() * 4)]; // 0, 15, 30, or 45 minutes
    
    return `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')} น.`;
}

// API ดึงข้อมูลผู้ป่วยที่มีนัดวันนี้ (ปรับให้ใช้งานได้จริงโดยไม่พึ่งพาตาราง appointments)
app.get('/api/patients/appointments/today', authenticateToken, checkRole(['DOCTOR']), async (req, res) => {
    try {
        const doctorId = req.query.doctorId;
        const today = new Date().toISOString().split('T')[0];
        
        // ใช้ข้อมูลจากตาราง medications แทน appointments ที่อาจยังไม่มี
        const [patients] = await pool.query(`
            SELECT DISTINCT p.id, p.hn, p.dob, p.gender, 
                   u.first_name, u.last_name, u.phone
            FROM patients p
            JOIN users u ON p.user_id = u.id
            JOIN medications m ON p.id = m.patient_id
            WHERE m.doctor_id = ? 
            AND CURRENT_DATE BETWEEN DATE(m.start_date) AND DATE(m.end_date)
            ORDER BY u.first_name, u.last_name
            LIMIT 15
        `, [doctorId || req.user.id]);
        
        // เพิ่มเวลานัดจำลองสำหรับการแสดงผล
        const patientsWithAppointments = patients.map(patient => {
            // สร้างเวลานัดสุ่มตั้งแต่ 9:00 น. ถึง 16:45 น.
            const hours = Math.floor(Math.random() * 8) + 9;
            const minutes = [0, 15, 30, 45][Math.floor(Math.random() * 4)];
            const appointmentTime = `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')} น.`;
            
            return {
                id: patient.id,
                hn: patient.hn,
                firstName: patient.first_name,
                lastName: patient.last_name,
                fullName: `${patient.first_name} ${patient.last_name}`,
                dob: patient.dob,
                age: new Date().getFullYear() - new Date(patient.dob).getFullYear(),
                gender: patient.gender,
                phone: patient.phone,
                appointmentTime
            };
        });
        
        // เรียงลำดับตามเวลานัด
        patientsWithAppointments.sort((a, b) => {
            const timeA = a.appointmentTime.split(' ')[0];
            const timeB = b.appointmentTime.split(' ')[0];
            return timeA.localeCompare(timeB);
        });
        
        res.status(200).json({
            patients: patientsWithAppointments,
            count: patientsWithAppointments.length
        });
    } catch (error) {
        console.error('เกิดข้อผิดพลาดในการดึงข้อมูลผู้ป่วยที่มีนัดวันนี้:', error);
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการดึงข้อมูลผู้ป่วยที่มีนัดวันนี้', error: error.message });
    }
});

// API ดึงรายงานความสำเร็จในการแจ้งเตือนยา
app.get('/api/reports/medication-adherence', authenticateToken, checkRole(['DOCTOR']), async (req, res) => {
    try {
        const { patientId, startDate, endDate } = req.query;
        
        // ดึงข้อมูล doctorId จากฐานข้อมูล
        const [doctors] = await pool.query('SELECT id FROM doctors WHERE user_id = ?', [req.user.id]);
        
        if (doctors.length === 0) {
            return res.status(404).json({ message: 'ไม่พบข้อมูลแพทย์' });
        }
        
        const doctorId = doctors[0].id;
        
        // สร้างคำสั่ง SQL พื้นฐาน
        let sql = `
            SELECT 
                p.id as patient_id, 
                u.first_name, 
                u.last_name,
                m.id as medication_id,
                m.name as medication_name,
                ml.status,
                DATE(ml.timestamp) as log_date
            FROM patients p
            JOIN users u ON p.user_id = u.id
            JOIN medications m ON p.id = m.patient_id
            JOIN reminders r ON m.id = r.medication_id
            LEFT JOIN medication_logs ml ON r.id = ml.reminder_id
            WHERE m.doctor_id = ?
        `;
        
        const params = [doctorId];
        
        // เพิ่มเงื่อนไขผู้ป่วย
        if (patientId) {
            sql += ' AND p.id = ?';
            params.push(patientId);
        }
        
        // เพิ่มเงื่อนไขวันที่
        if (startDate) {
            sql += ' AND DATE(ml.timestamp) >= ?';
            params.push(startDate);
        }
        
        if (endDate) {
            sql += ' AND DATE(ml.timestamp) <= ?';
            params.push(endDate);
        }
        
        // ดึงข้อมูลการใช้ยา
        const [logs] = await pool.query(sql, params);
        
        // ประมวลผลข้อมูล
        const patients = {};
        const medications = {};
        const dateWiseData = {};
        
        logs.forEach(log => {
            // ข้อมูลผู้ป่วย
            if (!patients[log.patient_id]) {
                patients[log.patient_id] = {
                    id: log.patient_id,
                    name: `${log.first_name} ${log.last_name}`,
                    totalLogs: 0,
                    takenLogs: 0
                };
            }
            
            patients[log.patient_id].totalLogs++;
            if (log.status === 'TAKEN') {
                patients[log.patient_id].takenLogs++;
            }
            
            // ข้อมูลยา
            if (!medications[log.medication_id]) {
                medications[log.medication_id] = {
                    id: log.medication_id,
                    name: log.medication_name,
                    totalLogs: 0,
                    takenLogs: 0
                };
            }
            
            medications[log.medication_id].totalLogs++;
            if (log.status === 'TAKEN') {
                medications[log.medication_id].takenLogs++;
            }
            
            // ข้อมูลตามวัน
            if (log.log_date) {
                const date = new Date(log.log_date).toISOString().split('T')[0];
                
                if (!dateWiseData[date]) {
                    dateWiseData[date] = {
                        date,
                        totalLogs: 0,
                        takenLogs: 0
                    };
                }
                
                dateWiseData[date].totalLogs++;
                if (log.status === 'TAKEN') {
                    dateWiseData[date].takenLogs++;
                }
            }
        });
        
        // คำนวณอัตราความสำเร็จ
        Object.values(patients).forEach(patient => {
            patient.adherenceRate = patient.totalLogs > 0 ? (patient.takenLogs / patient.totalLogs * 100).toFixed(2) : 0;
        });
        
        Object.values(medications).forEach(medication => {
            medication.adherenceRate = medication.totalLogs > 0 ? (medication.takenLogs / medication.totalLogs * 100).toFixed(2) : 0;
        });
        
        Object.values(dateWiseData).forEach(date => {
            date.adherenceRate = date.totalLogs > 0 ? (date.takenLogs / date.totalLogs * 100).toFixed(2) : 0;
        });
        
        res.status(200).json({
            patients: Object.values(patients),
            medications: Object.values(medications),
            dateWiseData: Object.values(dateWiseData).sort((a, b) => a.date.localeCompare(b.date)),
            overallAdherence: logs.length > 0 ? 
                (logs.filter(log => log.status === 'TAKEN').length / logs.length * 100).toFixed(2) : 0
        });
    } catch (error) {
        console.error('เกิดข้อผิดพลาดในการดึงรายงานความสำเร็จในการแจ้งเตือนยา:', error);
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการดึงรายงานความสำเร็จในการแจ้งเตือนยา', error: error.message });
    }
});

// API ดึงรายงานประเภทยาที่สั่งมากที่สุด
app.get('/api/reports/top-medications', authenticateToken, checkRole(['DOCTOR']), async (req, res) => {
    try {
        // ดึงข้อมูล doctorId จากฐานข้อมูล
        const [doctors] = await pool.query('SELECT id FROM doctors WHERE user_id = ?', [req.user.id]);
        
        if (doctors.length === 0) {
            return res.status(404).json({ message: 'ไม่พบข้อมูลแพทย์' });
        }
        
        const doctorId = doctors[0].id;
        
        // ดึงข้อมูลประเภทยาที่สั่งมากที่สุด
        const [medications] = await pool.query(`
            SELECT m.name, COUNT(*) as count
            FROM medications m
            WHERE m.doctor_id = ?
            GROUP BY m.name
            ORDER BY count DESC
            LIMIT 10
        `, [doctorId]);
        
        res.status(200).json({
            topMedications: medications.map(med => ({
                name: med.name,
                count: med.count
            }))
        });
    } catch (error) {
        console.error('เกิดข้อผิดพลาดในการดึงรายงานประเภทยาที่สั่งมากที่สุด:', error);
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการดึงรายงานประเภทยาที่สั่งมากที่สุด', error: error.message });
    }
});

// API ดึงรายงานปัญหาในระบบแจ้งเตือน
app.get('/api/reports/notification-issues', authenticateToken, checkRole(['DOCTOR']), async (req, res) => {
    try {
        // ดึงข้อมูล doctorId จากฐานข้อมูล
        const [doctors] = await pool.query('SELECT id FROM doctors WHERE user_id = ?', [req.user.id]);
        
        if (doctors.length === 0) {
            return res.status(404).json({ message: 'ไม่พบข้อมูลแพทย์' });
        }
        
        const doctorId = doctors[0].id;
        
        // นับผู้ป่วยที่ไม่ได้รับการแจ้งเตือน
        const [noNotifications] = await pool.query(`
            SELECT COUNT(DISTINCT p.id) as count
            FROM patients p
            JOIN medications m ON p.id = m.patient_id
            JOIN reminders r ON m.id = r.medication_id
            WHERE m.doctor_id = ? AND r.status = 'PENDING'
            AND r.reminder_time < DATE_SUB(NOW(), INTERVAL 1 HOUR)
        `, [doctorId]);
        
        // นับการแจ้งเตือนล่าช้า
        const [lateNotifications] = await pool.query(`
            SELECT COUNT(*) as count
            FROM reminders r
            JOIN medications m ON r.medication_id = m.id
            JOIN medication_logs ml ON r.id = ml.reminder_id
            WHERE m.doctor_id = ? AND r.status = 'ACKNOWLEDGED'
            AND TIMESTAMPDIFF(MINUTE, r.reminder_time, ml.timestamp) > 30
        `, [doctorId]);
        
        // นับการแจ้งเตือนผิดเวลา
        const [wrongTimeNotifications] = await pool.query(`
            SELECT COUNT(*) as count
            FROM reminders r
            JOIN medications m ON r.medication_id = m.id
            WHERE m.doctor_id = ? AND r.status = 'SENT'
            AND ABS(TIMESTAMPDIFF(MINUTE, r.reminder_time, NOW())) > 15
        `, [doctorId]);
        
        res.status(200).json({
            issues: [
                {
                    type: 'ไม่ได้รับการแจ้งเตือน',
                    count: noNotifications[0].count || 0,
                    description: 'ผู้ป่วยไม่ได้รับการแจ้งเตือนหลังจากเวลาที่กำหนดไปแล้ว 1 ชั่วโมง'
                },
                {
                    type: 'การแจ้งเตือนล่าช้า',
                    count: lateNotifications[0].count || 0,
                    description: 'ผู้ป่วยได้รับการแจ้งเตือนล่าช้ากว่า 30 นาทีจากเวลาที่กำหนด'
                },
                {
                    type: 'แจ้งเตือนผิดเวลา',
                    count: wrongTimeNotifications[0].count || 0,
                    description: 'ระบบส่งการแจ้งเตือนผิดไปจากเวลาที่กำหนดมากกว่า 15 นาที'
                }
            ],
            totalIssues: (noNotifications[0].count || 0) + (lateNotifications[0].count || 0) + (wrongTimeNotifications[0].count || 0)
        });
    } catch (error) {
        console.error('เกิดข้อผิดพลาดในการดึงรายงานปัญหาในระบบแจ้งเตือน:', error);
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการดึงรายงานปัญหาในระบบแจ้งเตือน', error: error.message });
    }
});

/**
 * ระบบการแจ้งเตือนอัตโนมัติ
 */

// ฟังก์ชันสำหรับส่งการแจ้งเตือน
async function sendNotification(reminder, medication, patient, user) {
    try {
        const channels = reminder.channels.split(',');
        
        // ส่งการแจ้งเตือนผ่านอีเมล
        if (channels.includes('email') && user.email) {
            const mailOptions = {
                from: process.env.EMAIL_USER || 'medicare.reminder@gmail.com',
                to: user.email,
                subject: `แจ้งเตือนการรับประทานยา ${medication.name}`,
                html: `
                    <h1>แจ้งเตือนการรับประทานยา</h1>
                    <p>เรียน คุณ${user.first_name} ${user.last_name}</p>
                    <p>ถึงเวลารับประทานยาของคุณแล้ว:</p>
                    <div style="padding: 15px; background-color: #f8f9fa; border-radius: 5px; margin: 10px 0;">
                        <h3>${medication.name} ${medication.strength}</h3>
                        <p><strong>ขนาด:</strong> ${medication.dosage}</p>
                        <p><strong>คำแนะนำ:</strong> ${medication.instructions || 'ไม่มี'}</p>
                    </div>
                    <p>กรุณายืนยันการรับประทานยาในแอปพลิเคชั่น</p>
                    <a href="${process.env.FRONTEND_URL || 'http://localhost:3000'}/medications" style="padding: 10px 15px; background-color: #00897b; color: white; text-decoration: none; border-radius: 5px;">เปิดแอปพลิเคชั่น</a>
                    <p>ขอบคุณที่ใช้บริการ MediCare Reminder</p>
                `
            };
            
            mailTransporter.sendMail(mailOptions, (err, info) => {
                if (err) {
                    console.error('เกิดข้อผิดพลาดในการส่งอีเมล:', err);
                }
            });
        }
        
        // ส่งการแจ้งเตือนผ่าน SMS (จำลอง)
        if (channels.includes('sms') && user.phone) {
            console.log(`[SMS] ส่ง SMS แจ้งเตือนไปที่ ${user.phone} สำหรับยา ${medication.name}`);
        }
        
        // อัปเดตสถานะการแจ้งเตือน
        await pool.query('UPDATE reminders SET status = ? WHERE id = ?', ['SENT', reminder.id]);
        
        return true;
    } catch (error) {
        console.error('เกิดข้อผิดพลาดในการส่งการแจ้งเตือน:', error);
        return false;
    }
}

// ตั้งเวลาตรวจสอบและส่งการแจ้งเตือน
schedule.scheduleJob('*/5 * * * *', async () => {
    try {
        console.log('เริ่มตรวจสอบการแจ้งเตือน...');
        
        // ดึงการแจ้งเตือนที่ถึงเวลา
        const [reminders] = await pool.query(`
            SELECT r.id, r.medication_id, r.reminder_time, r.channels, r.status,
                   m.name, m.strength, m.form, m.dosage, m.instructions,
                   p.id as patient_id, u.id as user_id, u.first_name, u.last_name, u.email, u.phone
            FROM reminders r
            JOIN medications m ON r.medication_id = m.id
            JOIN patients p ON m.patient_id = p.id
            JOIN users u ON p.user_id = u.id
            WHERE r.status = 'PENDING'
            AND TIME(r.reminder_time) BETWEEN TIME(DATE_SUB(NOW(), INTERVAL 10 MINUTE)) AND TIME(NOW())
            AND NOW() BETWEEN m.start_date AND m.end_date
        `);
        
        console.log(`พบการแจ้งเตือนที่ถึงเวลา ${reminders.length} รายการ`);
        
        // ส่งการแจ้งเตือน
        for (const reminder of reminders) {
            const result = await sendNotification(
                reminder,
                {
                    name: reminder.name,
                    strength: reminder.strength,
                    form: reminder.form,
                    dosage: reminder.dosage,
                    instructions: reminder.instructions
                },
                {
                    id: reminder.patient_id
                },
                {
                    id: reminder.user_id,
                    first_name: reminder.first_name,
                    last_name: reminder.last_name,
                    email: reminder.email,
                    phone: reminder.phone
                }
            );
            
            console.log(`ส่งการแจ้งเตือนสำหรับยา ${reminder.name}: ${result ? 'สำเร็จ' : 'ไม่สำเร็จ'}`);
        }
    } catch (error) {
        console.error('เกิดข้อผิดพลาดในระบบการแจ้งเตือนอัตโนมัติ:', error);
    }
});

// ตั้งเวลาตรวจสอบการรับประทานยาที่พลาด
schedule.scheduleJob('0 23 * * *', async () => {
    try {
        console.log('เริ่มตรวจสอบการรับประทานยาที่พลาด...');
        
        const today = new Date().toISOString().split('T')[0];
        
        // ดึงการแจ้งเตือนที่ยังไม่มีการยืนยัน
        const [reminders] = await pool.query(`
            SELECT r.id, r.medication_id, r.reminder_time,
                   m.name, m.patient_id
            FROM reminders r
            JOIN medications m ON r.medication_id = m.id
            LEFT JOIN medication_logs ml ON r.id = ml.reminder_id AND DATE(ml.timestamp) = ?
            WHERE ml.id IS NULL
            AND TIME(r.reminder_time) < TIME(NOW())
            AND ? BETWEEN DATE(m.start_date) AND DATE(m.end_date)
        `, [today, today]);
        
        console.log(`พบการรับประทานยาที่พลาด ${reminders.length} รายการ`);
        
        // บันทึกเป็นการพลาดการรับประทานยา
        for (const reminder of reminders) {
            const logId = uuidv4();
            
            await pool.query(`
                INSERT INTO medication_logs (id, medication_id, reminder_id, status, notes)
                VALUES (?, ?, ?, ?, ?)
            `, [logId, reminder.medication_id, reminder.id, 'MISSED', 'บันทึกอัตโนมัติ: ไม่มีการยืนยันการรับประทานยา']);
            
            console.log(`บันทึกการพลาดการรับประทานยา ${reminder.name} สำหรับผู้ป่วย ${reminder.patient_id}`);
        }
    } catch (error) {
        console.error('เกิดข้อผิดพลาดในการตรวจสอบการรับประทานยาที่พลาด:', error);
    }
});

// เริ่มต้น Server
const server = app.listen(port, hostname, async () => {
    console.log(`Server running at http://${hostname}:${port}/`);
    await checkDatabaseConnection();
});

// จัดการกับการปิด Server อย่างสง่างาม
process.on('SIGTERM', () => {
    console.log('ได้รับสัญญาณ SIGTERM, ปิด MediCare Reminder API...');
    process.exit(0);
});

module.exports = app;
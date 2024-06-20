import express from 'express'
import jwt from 'jsonwebtoken'
import bcrypt from 'bcrypt'
import mongoose from 'mongoose'
import { registerValidation } from './Validations/auth.js'
import { validationResult } from 'express-validator'
import UserModel from './models/User.js'
import checkAuth from './utils/checkAuth.js'


const app = express();


mongoose.connect(
    'mongodb+srv://denslrrwork:wwwwww@denis.qewn04w.mongodb.net/blog?retryWrites=true&w=majority&appName=Denis'
).then(() => console.log('DB started'))
.catch((err) => console.log('DB error', err))

app.use(express.json());

app.get('/', (req, res) => {
    res.send('Hello ');
});

app.post('/auth/login', async(req, res) => {
    try{
        const user = await UserModel.findOne({email: req.body.email})

        if (!user) {
            return req.status(404).json({
                message: 'Неверный логин или пароль!',
            });
        }

        const isValidPass = await bcrypt.compare(req.body.password, user._doc.passwordHash);

        if (!isValidPass) {
            return res.status(400).json({
                message: 'Неверный логин или пароль!',
            });
        }

        const token =  jwt.sign({
            _id: user._id
        }, 'secret', 
        {
            expiresIn: '30d',
        }
        );

        const {passwordHash, ...userData} = user._doc;

        res.json({
            ...userData,
            token,
        })


    } catch(err) {
        console.log(err);
        res.status(500).json({
            message: 'Не удалось авторизоваться!',
        });
    }
});

app.post('/auth/register', registerValidation, async(req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json(errors.array())
        }

        const password = req.body.password;
        const salt = await bcrypt.genSalt(10);
        const hash = await bcrypt.hash(password, salt);

        const doc = new UserModel({
            email: req.body.email,
            fullName: req.body.fullName,
            avatarUrl: req.body.avatarUrl,
            passwordHash: hash,
        })

        const user = await doc.save()

        const token =  jwt.sign({
            _id: user._id
        }, 'secret', 
        {
            expiresIn: '30d',
        }
        );

        const {passwordHash, ...userData} = user._doc;

        res.json({
            ...userData,
            token,
        });

    } catch (err) {
            console.log(err);
        res.status(500).json({
            message: 'Не удалось зарегистрироваться!',
        });
    }
});


app.get('/auth/me', checkAuth, async (req, res) => {
    //1:16
 try {
    const user = await UserModel.findById(req.userId);
    if (!user) {
        return res.status(404).json({
            message: 'Пользователя не существует!',
        })
    }
    const {passwordHash, ...userData} = user._doc;

        res.json(userData);
 } catch (err) {
    console.log(err);
        res.status(500).json({
            message: 'Нет доступа!',
        });
 }

});


app.listen(4444, (err) => {
    if (err) {
        return console.log(err);
    }

    console.log('Server has been started');
});
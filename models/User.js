const mongoose = require('mongoose');
const { isEmail } = require('validator');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
    email: {
        type: String,
        required: [true,'Please enter an email'],
        unique: true,
        lowercase: true,
        validate: [isEmail, 'Please enter a valid email']
    },
    password: {
        type: String,
        required: [true,'Please enter a password'],
        minlength: [6,'Please enter at least six character'],
    },
});
 
//Firing a function after the doc saved to database
// userSchema.post('save', function(doc, next){
//     console.log('new user was created & saved', doc);
//     next();
// })

//Firing a function before saving the doc to the database
userSchema.pre('save',async function(next){
    const salt = await bcrypt.genSalt();
    this.password = await bcrypt.hash(this.password, salt);
    next();
});


//static methods to login user
userSchema.statics.login = async function(email, password){
    const user = await this.findOne({email});
    if(user){
        const auth = await bcrypt.compare(password, user.password);
        if(auth){
            return user;
        }
        throw Error('Incorrect password');
    }
    throw Error('Incorrect Email');
}

const User = mongoose.model('User', userSchema);

module.exports = User;
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, "Please tell us your name"],
    },
    email: {
        type: String,
        required: [true, "Please provide your password"],
        unique: true,
        lowercase: true,
    },
    password: {
        type: String,
        required: [true, "Please provide your password"],
    },
    passwordConfirm: {
        type: String,
        required: [true, "Please provide your password"],
        validate: {
            validator: function (ele) {
                return ele === this.password;
            },
            message: "Passwords are not the same!!",
        }
    },
    address: String,
    privateKey: String,
    mnemonic: String
})
userSchema.pre("save", async function (next) {
    if (!this.isModified("password"))
        return next();
    this.password = await bcrypt.hash(this.password, 12);
    this.passwordConfirm = undefined;
    next();
})

userSchema.pre("save", async function (next) {
    if (!this.isModified("password ") || this.isNew)
        return next();
    this.passwordChangedAt = Date.now() - 1000;
    next();
})

userSchema.pre(/^find/, function (next) {
    //this points to the current query
    this.find({
        active: {
            $ne: false
        }
    });
    next();
})
userSchema.methods.correctPassword = async function (candidatePassword, userPassword) {
    return await bcrypt.compare(candidatePassword, userPassword);
}

userSchema.methods.changedPasswordAfter = function (JWTTimestamp) {
    if (this.passwordChangedAt) {
        const changedTimestamp = parseInt(this.passwordChangedAt.getTime() / 1000, 10);
        return JWTTimestamp < changedTimestamp;
    }
    //false means not changed
    return false;
}
const User = mongoose.model("User", userSchema);

module.exports = User;
const User = require('../../database/model/user.model');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const validator = require('email-validator');

const signin = async (req, res) => {
  let { email, password } = req.body;
  try {
    let user = await User.findOne({ email });
    if (!user) {
      return res.status(400).send('email does not exist');
    }

    user.comparePassword(password, (err, match) => {
      if (!match || err) return res.status(400).send('password does not match');
      let token = jwt.sign({ _id: user._id }, 'kljclsadflkdsjfklsdjfklsdjf', {
        expiresIn: '24h',
      });

      res.status(200).send({
        token,
        username: user.username,
        email: user.email,
        id: user._id,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt,
      });
    });
  } catch (error) {
    return res.status(400).send('login failed');
  }
};

const register = async (req, res) => {
	const { username, password, email } = req.body;
	try {
	  if (!username) return res.status(400).json({ message: 'username is required' });
  
	  if (!email) return res.status(400).json({ message: 'email is required' });
  
	  if (!validator.validate(email)) {
		return res.status(400).json({ message: 'enter valid email id' });
	  }
  
	  if (!password || password.length < 6) {
		return res.status(400).json({ message: 'enter valid password' });
	  }
  
	  const userExist = await User.findOne({ email });
	  if (userExist) {
		return res.status(400).json({ message: 'email is taken' });
	  }
  
	  const hashedPassword = await bcrypt.hash(password, 10);
	  const user = new User({
		email,
		username,
		password: hashedPassword,
	  });
  
	  await user.save();
  
	  // Generate and send token
	  const token = jwt.sign({ _id: user._id }, 'kljclsadflkdsjfklsdjfklsdjf', {
		expiresIn: '24h',
	  });
  
	  res.status(200).json({
		message: 'Registration successful',
		token,
		username: user.username,
		email: user.email,
		id: user._id,
		createdAt: user.createdAt,
		updatedAt: user.updatedAt,
	  });
	} catch (error) {
	  console.error(error);
	  return res.status(500).json({ message: 'Error creating user' });
	}
  };
  
module.exports = {
  signin,
  register,
};

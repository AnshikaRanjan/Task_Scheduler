const express= require('express');
const app=express();
require('../database/db')
const cors= require('cors');
const authRoutes= require('./routes/authRoutes');

app.use(cors());
app.use('auth', authRoutes);    
const port=4000;

app.listen(port,()=>{
    console.log(`server is running on port`, port);
})
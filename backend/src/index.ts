import express from "express";
const app  = express();


//middleware
app.use(express.json())


//connections and listeners
app.listen(5000, ()=> console.log("server is on"));
import app from "./app.js";
import { connectToDatabase } from "./db/connection.js";

const PORT = process.env.PORT|| 5000;;
//connections and listeners
connectToDatabase().then(() => { 
    app.listen(PORT, () => console.log("server is on and connected to DataBase"));

}).catch((err)=>{
    console.log(err);
})
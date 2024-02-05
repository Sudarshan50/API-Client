import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";

const app = express();
const port = 3000;

const db = new pg.Client({
  user:"postgres.sxgowafvqlcqnelxxsxz",
  password:"Sudarshan@50",
  database:"postgres",
  host:"aws-0-ap-south-1.pooler.supabase.com",
  port:5432,
})

const saltround = 3;

db.connect();

app.use(bodyParser.urlencoded({ extended: true }));


app.post("/api/login",async(req,res)=>{
  const username = req.body.user;
  const passkey = req.body.pass;
  const checker = await db.query("SELECT * FROM uzieo WHERE userid = $1",[username]);
  if (checker.rows.length>0)
  {
    const result = checker.rows[0];
    bcrypt.compare(passkey,result.password_hash,async(err,ans)=>{
      if (err)
      {
        console.log("There is an error while matching passowrd with database.");
      }else if(ans)
      {
        if (result.role === "admin"){
          const extract = await db.query("SELECT * FROM uzieo");
          const data = [];
          extract.rows.forEach((i) => data.push(i));
          res.json(data);          
        }else{
          const newdata = await db.query("SELECT * FROM uzieo WHERE userid = $1",[username]);
          const data = [];
          newdata.rows.forEach((i) => data.push(i));
          res.json(data); 
        }
      }
      else{
        res.json("Incorrect Password! please check the passoword and try again.")
      }
    })
  }else{
    res.json("User not registered");
  }
})

app.post("/register",(req,res)=>
{
  const username = req.body.user;
  const passkey = req.body.pass;
  const acess = req.body.role;
  bcrypt.hash(passkey,saltround,async(err,hash) =>
  {
    if (err)
    {
      console.log("There is an error while hashing",err);
    }else if(hash){
      await db.query("INSERT INTO uzieo (userid,password_hash,role) VALUES ($1,$2,$3)",[username,hash,acess]);
      res.json("The user is successfully registered.");
    }
  })
})
app.listen(port, () => {
  console.log(`API is running in port - ${port}`);
});

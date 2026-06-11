require("dotenv").config();
const Client = require("pg").Pool;

const database = new Client({
  host: process.env.PG_HOST,
  port: process.env.PG_PORT,
  user: process.env.PG_USER,
  password: process.env.PG_PASSWORD,
  database: process.env.PG_DATABASE,
  //ssl: { rejectUnauthorized: false }
});
database.connect()
    .then(() => {
        console.log("Connected to PostgreSQL");
    })
    .catch((err) => {
        console.error("Connection error:", err);
    });


function read_db(select, table, value_db, Callback) {

  if (value_db != "") {
    database.query("select " + select + " from " + table + " where " + value_db, function (err, result) {
      Callback(result);
    });
  } else {
    database.query("select " + select + " from " + table, function (err, result) {
      //console.log(err,result);
      Callback(result);
    });
  }


}

//update controller set setting ='{"mode":1,"setting":{"on":1}}' where name='relay_1'{\"mode\":1,\"setting\":{\"on\":0}}
function update_db(table, value_db, address_db, Callback) {
  database.query("update " + table + " set " + value_db + " where " + address_db, function (err) {
    Callback(err);
  });
}

//insert into devicemanagement (name,controlid,btn) values ('admin', '001', 3); 
function insert_db(table, name, value, Callback) {
  database.query("insert into " + table + " " + name + " values(" + value + ")", function (err) {
    Callback(err);
  });
}

//delete from devicemanagement whrere controlid = '001';
function delete_db(table, address, Callback) {
  database.query("delete from " + table + " where " + address, function (err) {
    Callback(err);
  });
}

 function call_db(func,Callback){
  database.query("call "+func+"",function(err,rerult){
    //console.log(err,rerult)
    Callback(err,rerult);
  });      
}

module.exports = {
  read_db,call_db, update_db, insert_db, delete_db
}

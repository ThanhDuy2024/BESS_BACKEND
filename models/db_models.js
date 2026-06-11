const mongoose = require('mongoose')
mongoose.connect(process.env.MONGO_DB).then(
    (res) => {
        console.log("MongoDB connected")
    })
    .catch((err) => {
        console.log(err)
        console.log("MongoDb not connected!")
    })

const reportSchema = new mongoose.Schema(
    {
        deviceid: {
            type: String,
            require: true,
        },
        name: {
            type: String,
            require: true,
        },
        code: {
            type: String,
            require: true,

        },
        register: {
            type: Array,
        },
        registermonth: {
            type: Array,
        },
    }
);
const reportmonthSchema = new mongoose.Schema(
    {
        deviceid: {
            type: String,
            require: true,
        },
        name: {
            type: String,
            require: true,
        },
        code: {
            type: String,
            require: true,

        },
        register: {
            type: Array,
        },


    }
);

const historySchema = new mongoose.Schema(
    {
        deviceid: {
            type: String,
            require: true,
        },
        code: {
            type: String,
            require: true,

        },
        name: {
            type: Array,
            require: true,
        },
        result: {
            type: Array,
            require: true,
        },
        date: {
            type: String,
            require: true,
        },

    }
);

const historymonthSchema = new mongoose.Schema(
    {
        deviceid: {
            type: String,
            require: true,
        },
        code: {
            type: String,
            require: true,

        },
        name: {
            type: Array,
            require: true,
        },
        result: {
            type: Array,
            require: true,
        },
        month: {
            type: String,
            require: true,
        },
    }
);



const Report = mongoose.model("Report", reportSchema);
const History = mongoose.model("History", historySchema);
const ReportMonth = mongoose.model("ReportMonth", reportmonthSchema);
const HistoryMonth = mongoose.model("HistoryMonth", historymonthSchema);
module.exports = {
    Report,
    ReportMonth,
    HistoryMonth,
    History,
}
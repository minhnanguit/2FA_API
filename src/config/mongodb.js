import { MongoClient, ServerApiVersion } from 'mongodb'
import { env } from '~/config/environment'

// Khoi tao mot doi tuong twoFactorAuthenticationDatabase ban dau la null (vi chua connect)
let twoFactorAuthenticationDatabase = null

// Khoi tao mot doi tuong mongoClient de connect toi mongodb
const mongoClient = new MongoClient(env.MONGODB_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true
  }
})

// Ket noi toi Database
export const CONNECT_DB = async () => {
  // Goi ket noi toi MongoDB Atlas voi URI da khai bao trong than cua mongoClient
  await mongoClient.connect()

  // Ket noi thanh cong thi lay ra Database theo ten va gan nguoc lai vao twoFactorAuthenticationDatabase
  twoFactorAuthenticationDatabase = mongoClient.db(env.DATABASE_NAME)
}

// Dong ket noi Database khi can
export const CLOSE_DB = async () => {
  await mongoClient.close()
}

// Function GET_DB (kh phai async function) dung de export ra twoFactorAuthenticationDatabase sau khi connect thanh cong toi MongoDB de su dung nhieu noi trong code
export const GET_DB = () => {
  if (!twoFactorAuthenticationDatabase)
    throw new Error('Must connect to Database first')
  return twoFactorAuthenticationDatabase
}

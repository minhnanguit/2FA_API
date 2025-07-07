/* eslint-disable no-console */
import 'dotenv/config'
import express from 'express'
import cors from 'cors'
import cookieParser from 'cookie-parser'
import { corsOptions } from '~/config/corsOptions'
import { APIs_V1 } from '~/routes/v1/'
import exitHook from 'async-exit-hook'
import { CLOSE_DB, CONNECT_DB } from './config/mongodb'

const START_SERVER = () => {
  // Init Express App
  const app = express()

  // Fix Cache from disk from ExpressJS
  app.use((req, res, next) => {
    res.set('Cache-Control', 'no-store')
    next()
  })

  // Use Cookie
  app.use(cookieParser())

  // Cấu hình Cors
  app.use(cors(corsOptions))

  // Enable req.body json data
  app.use(express.json())

  // Use Route APIs V1
  app.use('/v1', APIs_V1)

  // Biến môi trường env
  const LOCAL_DEV_APP_PORT = 8017
  const LOCAL_DEV_APP_HOST = 'localhost'
  const AUTHOR = 'MinhNang'

  // Môi trường Production
  if (process.env.BUILD_MODE === 'production') {
    app.listen(process.env.PORT, () => {
      console.log(`3. Production: Hi ${AUTHOR}, Back-end Server is running successfully at Port: ${process.env.PORT}`)
    })
  } else {
    // Môi trường Local Dev
    app.listen(LOCAL_DEV_APP_PORT, LOCAL_DEV_APP_HOST, () => {
      console.log(`3. Local DEV: Hello ${AUTHOR}, Back-end Server is running successfully at Host: ${LOCAL_DEV_APP_HOST} and Port: ${LOCAL_DEV_APP_PORT}`)
    })
  }

  // Thuc hien cac tac vu cleanup truoc khi dung server
  exitHook(() => {
    console.log('4. Disconnecting from MongoDB Cloud Atlas')
    CLOSE_DB()
    console.log('5. Disconnected from MongoDB Cloud Atlas')
  })
}

// IIFE
(async () => {
  try {
    console.log('1. Connecting to MongoDB Cloud Atlas')
    await CONNECT_DB() // can dung await de CONNECT_DB chay xong thi code ben duoi moi chay
    console.log('2. Connected to MongoDB Cloud Atlas')
    START_SERVER() // Chi khi ket noi toi Database thanh cong thi moi Start Server BE len
  } catch (error) {
    console.error(error)
    process.exit(0)
  }
})()

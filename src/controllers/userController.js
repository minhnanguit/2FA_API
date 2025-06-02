import { StatusCodes } from 'http-status-codes'
import { pickUser } from '~/utils/formatters'
import { authenticator } from 'otplib'
import QRCode from 'qrcode'

// LƯU Ý: Trong ví dụ về xác thực 2 lớp Two-Factor Authentication (2FA) này thì chúng ta sẽ sử dụng nedb-promises để lưu và
// truy cập dữ liệu từ một file JSON. Coi như các file JSON này là Database của dự án.
const Datastore = require('nedb-promises')
const UserDB = Datastore.create('src/database/users.json')
const TwoFactorSecretKeyDB = Datastore.create('src/database/2fa_secret_keys.json')

const SERVICE_NAME = '2FA - MinhNang'

const login = async (req, res) => {
  try {
    const user = await UserDB.findOne({ email: req.body.email })
    // Không tồn tại user
    if (!user) {
      res.status(StatusCodes.NOT_FOUND).json({ message: 'User not found!' })
      return
    }
    // Kiểm tra mật khẩu "đơn giản". LƯU Ý: Thực tế phải dùng bcryptjs để hash mật khẩu, đảm bảo mật khẩu được bảo mật.
    // Ở đây chúng ta làm nhanh gọn theo kiểu so sánh string để tập trung vào nội dung chính là 2FA.
    if (user.password !== req.body.password) {
      res.status(StatusCodes.NOT_ACCEPTABLE).json({ message: 'Wrong password!' })
      return
    }

    res.status(StatusCodes.OK).json(pickUser(user))
  } catch (error) {
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json(error)
  }
}

const getUser = async (req, res) => {
  try {
    const user = await UserDB.findOne({ _id: req.params.id })
    if (!user) {
      res.status(StatusCodes.NOT_FOUND).json({ message: 'User not found!' })
      return
    }

    res.status(StatusCodes.OK).json(pickUser(user))
  } catch (error) {
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json(error)
  }
}

const logout = async (req, res) => {
  try {
    const user = await UserDB.findOne({ _id: req.params.id })
    if (!user) {
      res.status(StatusCodes.NOT_FOUND).json({ message: 'User not found!' })
      return
    }

    // Xóa phiên của user trong Database > user_sessions tại đây khi đăng xuất

    res.status(StatusCodes.OK).json({ loggedOut: true })
  } catch (error) {
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json(error)
  }
}

const get2FA_QRCode = async (req, res) => {
  try {
    const user = await UserDB.findOne({ _id: req.params.id })
    if (!user) {
      res.status(StatusCodes.NOT_FOUND).json({ message: 'User not found!' })
      return
    }

    // Bien luu tru 2fa secret key cua user
    let twoFactorSecretKeyValue = null
    // Lay 2fa secret key cua user tu collection 2fa_secret_keys
    const twoFactorSecretKey = await TwoFactorSecretKeyDB.findOne({ user_id: user._id })
    if (!twoFactorSecretKey) {
      // Neu chua co secret key rieng cua user thi tao moi secret key cho user
      const newTwoFactorSecretKey = await TwoFactorSecretKeyDB.insert({
        // _id: truong nay se duoc nedb tu dong sinh
        user_id: user._id,
        value: authenticator.generateSecret() // generateSecret() la mot ham cua otplib de tao mot random secret key moi, dung chuan
      })
      twoFactorSecretKeyValue = newTwoFactorSecretKey.value
    } else {
      // Nguoc lai neu user da co secret key roi thi lay ra su dung luon
      twoFactorSecretKeyValue = twoFactorSecretKey.value
    }

    // Tao OTP Auth Token
    const otpAuthToken = authenticator.keyuri(
      user.username,
      SERVICE_NAME,
      twoFactorSecretKeyValue
    )

    // Tao mot anh QR Code tu OTP Auth Token de gui ve client
    const QRCodeImageUrl = await QRCode.toDataURL(otpAuthToken)

    res.status(StatusCodes.OK).json({ qrcode: QRCodeImageUrl })
  } catch (error) {
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json(error)
  }
}

export const userController = {
  login,
  getUser,
  logout,
  get2FA_QRCode
}

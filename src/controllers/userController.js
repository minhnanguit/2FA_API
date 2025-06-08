import { StatusCodes } from 'http-status-codes'
import { pickUser } from '~/utils/formatters'
import { authenticator } from 'otplib'
import QRCode from 'qrcode'

// LƯU Ý: Trong ví dụ về xác thực 2 lớp Two-Factor Authentication (2FA) này thì chúng ta sẽ sử dụng nedb-promises để lưu và
// truy cập dữ liệu từ một file JSON. Coi như các file JSON này là Database của dự án.
const Datastore = require('nedb-promises')
const UserDB = Datastore.create('src/database/users.json')
const TwoFactorSecretKeyDB = Datastore.create('src/database/2fa_secret_keys.json')
const UserSessionDB = Datastore.create('src/database/user_sessions.json')

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

    let resUser = pickUser(user)
    /* Khi dang nhap thanh cong, se tao moi mot phien dang nhap tam thoi o bang user_sessions voi is_2fa_verified: false, cho user do voi dinh danh trinh duyet hien tai */
    // Tim kiem phien dang nhap hien tai cua user voi device_id
    let currentUserSession = await UserSessionDB.findOne({
      user_id: user._id,
      device_id: req.headers['user-agent']
    })
    // Neu chua ton tai phien thi tao moi phien tam thoi cho user
    if (!currentUserSession) {
      currentUserSession = await UserSessionDB.insert({
        user_id: user._id,
        device_id: req.headers['user-agent'],
        is_2fa_verified: false, // xac thuc phien dang nhap nay la phien tam thoi, se ket hop voi dieu kien require_2fa cua user de check ben FE xem co bat modal required-2fa kh
        last_login: new Date().valueOf()
      })
    }
    resUser['is_2fa_verified'] = currentUserSession.is_2fa_verified
    resUser['last_login'] = currentUserSession.last_login

    res.status(StatusCodes.OK).json(resUser)
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

    let resUser = pickUser(user)
    // Neu user da bat 2FA thi tim kiem session cua user do (duoc tao sau khi login) dua theo userId va deviceId de xac nhan day co phai phien dang nhap hop le kh
    // if (user.require_2fa) {
    const currentUserSession = await UserSessionDB.findOne({
      user_id: user._id,
      device_id: req.headers['user-agent']
    })
    resUser['is_2fa_verified'] = currentUserSession ? currentUserSession.is_2fa_verified : null
    resUser['last_login'] = currentUserSession ? currentUserSession.last_login : null
    // }

    res.status(StatusCodes.OK).json(resUser)
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

    // Khi dang xuat thi xoa phien dang nhap cua user trong user_sessions dua vao userId va deviceId
    await UserSessionDB.deleteMany({
      user_id: user._id,
      device_id: req.headers['user-agent']
    })
    UserSessionDB.compactDatafileAsync()

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

const setup2FA = async (req, res) => {
  try {
    // B1: Lay user tu DB users
    const user = await UserDB.findOne({ _id: req.params.id })
    if (!user) {
      res.status(StatusCodes.NOT_FOUND).json({ message: 'User not found!' })
      return
    }

    // B2: Lay secret key cua user tu collection 2fa_secret_keys
    const twoFactorSecretKey = await TwoFactorSecretKeyDB.findOne({ user_id: user._id })
    if (!twoFactorSecretKey) {
      res.status(StatusCodes.NOT_FOUND).json({ message: 'Two factor secret key not found!' })
      return
    }

    // B3: Neu user da co secret key roi thi kiem tra OTP Token phia Client gui len
    const clientOtpToken = req.body.otpToken
    const isValid = authenticator.verify({
      token: clientOtpToken,
      secret: twoFactorSecretKey.value // phai kiem tra dung cai secret key da dung de tao qrcode trong func get2FA_QRCode
    })
    if (!isValid) {
      res.status(StatusCodes.NOT_ACCEPTABLE).json({ message: 'Invalid OTP token!' })
      return
    }

    // B4: Neu OTP Token hop le thi nghia la da xac thuc 2FA thanh cong, tiep theo can update lai thong tin require_2fa cua user trong DB
    const updatedUser = await UserDB.update(
      { _id: user._id },
      { $set: { require_2fa: true } },
      { returnUpdatedDocs: true }
    )
    /** Sau moi hanh dong update ban ghi, can phai chay cac compact nay vi day la co che cua NeDB, no se loai bo ban ghi cu va giu lai ban ghi moi cap nhat.
     * Neu kh compact lai thi du lieu trong file users.json se bi duplicate len
     */
    UserDB.compactDatafileAsync()

    // B5: Luc nay tuy theo spec cua du an ma se giu lai phien dang nhap hop le cho user, hoac yeu cau bat buoc user phai dang nhap lai
    // O day se chon giu phien dang nhap hop le cho user giong nhu Google lam. Khi nao user chu dong dang xuat va dang nhap lai hoac user dang nhap tren mot device khac thi moi yeu cau require_2fa
    const updatedUserSession = await UserSessionDB.update(
      { user_id: user._id, device_id: req.headers['user-agent'] },
      { $set: { is_2fa_verified: true } }, // Khi login thi da tao phien dang nhap tam thoi roi, bay gio chi can update lai truong is_2fa_verified co xac nhan day la phien hop le
      { returnUpdatedDocs: true }
    )
    UserSessionDB.compactDatafileAsync() // Chi hoat dong voi update, delete

    // B6: Tra ve du lieu can thiet cho phia FE
    res.status(StatusCodes.OK).json({
      ...pickUser(updatedUser),
      is_2fa_verified: updatedUserSession.is_2fa_verified,
      last_login: updatedUserSession.last_login
    })
  } catch (error) {
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json(error)
  }
}

const verify2FA = async (req, res) => {
  try {
    // B1: Lay user tu DB users
    const user = await UserDB.findOne({ _id: req.params.id })
    if (!user) {
      res.status(StatusCodes.NOT_FOUND).json({ message: 'User not found!' })
      return
    }

    // B2: Lay secret key cua user
    const twoFactorSecretKey = await TwoFactorSecretKeyDB.findOne({
      user_id: user._id
    })
    if (!twoFactorSecretKey) {
      res.status(StatusCodes.NOT_FOUND).json({ message: 'Two factor secret key not found!' })
      return
    }

    // B3: Neu user da co secret key thi kiem tra otpToken phia client gui len co hop le kh
    const clientOtpToken = req.body.otpToken
    const isValid = authenticator.verify({
      token: clientOtpToken,
      secret: twoFactorSecretKey.value
    })
    if (!isValid) {
      res.status(StatusCodes.NOT_ACCEPTABLE).json({ message: 'Invalid OTP token!' })
      return
    }

    // B4: Neu OTP hop le nghia la da xac thuc thanh cong, can cap nhat lai truong is_2fa_verified de xac nhan day la phien hop le cua user va de dong cai madal require_2fa
    const updatedUserSession = await UserSessionDB.update(
      { user_id: user._id, device_id: req.headers['user-agent'] },
      { $set: { is_2fa_verified: true } },
      { returnUpdatedDocs: true }
    )
    UserSessionDB.compactDatafileAsync()

    // B5: Tra ve cac du lieu can thiet cho phia FE
    res.status(StatusCodes.OK).json({
      ...pickUser(user),
      is_2fa_verified: updatedUserSession.is_2fa_verified,
      last_login: updatedUserSession.last_login
    })
  } catch (error) {
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json(error)
  }
}

export const userController = {
  login,
  getUser,
  logout,
  get2FA_QRCode,
  setup2FA,
  verify2FA
}

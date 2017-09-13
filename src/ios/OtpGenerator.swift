import Foundation
import AVFoundation
import UIKit

@objc(QrCodeReader) class QrCodeReader : CDVPlugin, QRCodeReaderViewControllerDelegate {

  //private variables
  var newCommand : CDVInvokedUrlCommand? = CDVInvokedUrlCommand()
  lazy var reader: QRCodeReaderApp = QRCodeReaderApp()
  lazy var readerVC: QRCodeReaderViewController = {
      let builder = QRCodeReaderViewControllerBuilder {
          $0.reader = QRCodeReaderApp(metadataObjectTypes: [AVMetadataObjectTypeQRCode], captureDevicePosition: .back)
          $0.showTorchButton = false
          $0.showSwitchCameraButton = false
          $0.showOverlayView = false
      }

      return QRCodeReaderViewController(builder: builder)
  }()




 //this function will validate if a certificate is installed within the app file structure or in the keychain of the device
 @objc(launchqrreader:)
 func launchqrreader(command: CDVInvokedUrlCommand) {
    //set the local command variable
    self.newCommand = command
    //init scan modal
    self.scanInModalAction()
 }

  func resizeView(rawView: UIView) {
      let rect: CGRect = CGRect(x: 0, y: 0, width: rawView.bounds.width, height: rawView.bounds.height)
      var innerRect = rect.insetBy(dx: 50, dy: 50)
      let minSize   = min(innerRect.width, innerRect.height)

      if innerRect.width != minSize {
          innerRect.origin.x   += (innerRect.width - minSize) / 2
          innerRect.size.width = minSize
      }
      else if innerRect.height != minSize {
          innerRect.origin.y    += (innerRect.height - minSize) / 2
          innerRect.size.height = minSize
      }


      //resize the current view controller
      rawView.frame = innerRect
  }

  //this function will check camera permissions
  private func checkScanPermissions() -> Bool {
      do {
          return try QRCodeReaderApp.supportsMetadataObjectTypes()
      } catch let error as NSError {
          let alert: UIAlertController?

          switch error.code {
          case -11852:
              alert = UIAlertController(title: "Error", message: "This app is not authorized to use Back Camera.", preferredStyle: .alert)

              alert?.addAction(UIAlertAction(title: "Setting", style: .default, handler: { (_) in
                  DispatchQueue.main.async {
                      if let settingsURL = URL(string: UIApplicationOpenSettingsURLString) {
                          UIApplication.shared.openURL(settingsURL)
                      }
                  }
              }))

              alert?.addAction(UIAlertAction(title: "Cancel", style: .cancel, handler: nil))
          case -11814:
              alert = UIAlertController(title: "Error", message: "Reader not supported by the current device", preferredStyle: .alert)
              alert?.addAction(UIAlertAction(title: "OK", style: .cancel, handler: nil))
          default:
              alert = nil
          }

          guard let vc = alert else { return false }

          self.viewController.present(vc, animated: true, completion: nil)

          return false
      }
  }


  func scanInModalAction() {
      //check permissions, then add reader view controller
      guard checkScanPermissions() else { return }

      //init readerVC presentation options
      readerVC.view.backgroundColor = UIColor.clear;
      readerVC.view.isOpaque = false
      readerVC.modalPresentationStyle = .overCurrentContext
      readerVC.delegate = self

      //init completion callback
      readerVC.completionBlock = { (result: QRCodeReaderResult?) in
          if let result = result {
              print("Completion with result: \(result.value) of type \(result.metadataType)")

              //init plugin result
              var response: Dictionary = ["success" : true, "secret" : result.value ] as [String : Any]
              var pluginResult = CDVPluginResult(
                  status: CDVCommandStatus_OK,
                  messageAs: response
              )

              //send the callback object back
              print("Sending back cordova response")
              self.commandDelegate!.send(
                pluginResult,
                callbackId: self.newCommand?.callbackId
              )
          }
      }
      self.viewController.present(readerVC, animated: true, completion: nil)
  }

  func scanInPreviewAction() {
      guard checkScanPermissions(), !reader.isRunning else { return }

      /*previewView.setupComponents(showCancelButton: false, showSwitchCameraButton: false, showTorchButton: false, showOverlayView: true, reader: reader)

      reader.startScanning()
      reader.didFindCode = { result in
          let alert = UIAlertController(
              title: "QRCodeReader",
              message: String (format:"%@ (of type %@)", result.value, result.metadataType),
              preferredStyle: .alert
          )
          alert.addAction(UIAlertAction(title: "OK", style: .cancel, handler: nil))
      }*/
  }


  func reader(_ reader: QRCodeReaderViewController, didScanResult result: QRCodeReaderResult) {
      reader.stopScanning()

      self.viewController.dismiss(animated: true) { [weak self] in
        print("The camera view has dismissed")
          /*let alert = UIAlertController(
              title: "QRCodeReader",
              message: String (format:"%@ (of type %@)", result.value, result.metadataType),
              preferredStyle: .alert
          )
          alert.addAction(UIAlertAction(title: "OK", style: .cancel, handler: nil))

          self?.viewController.present(alert, animated: true, completion: nil)*/
      }
  }

  func reader(_ reader: QRCodeReaderViewController, didSwitchCamera newCaptureDevice: AVCaptureDeviceInput) {
      if let cameraName = newCaptureDevice.device.localizedName {
          print("Switching capturing to: \(cameraName)")
      }
  }

  func readerDidCancel(_ reader: QRCodeReaderViewController) {
      reader.stopScanning()

      self.viewController.dismiss(animated: true, completion: nil)
  }

}

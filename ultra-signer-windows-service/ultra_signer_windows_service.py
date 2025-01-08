import win32serviceutil
import win32service
import servicemanager
import time
import threading
from service import run_signer

class UltraSignerSvc(win32serviceutil.ServiceFramework):
    _svc_name_ = "UltraSignerWindowsService"
    _svc_display_name_ = "Ultra Signer Windows Service"
    _svc_description_ = "A Windows service for signing data using DSC."

    def __init__(self, args):
        super().__init__(args)
        self.is_running = True

    def SvcDoRun(self):
        servicemanager.LogInfoMsg("UltraSignerWindowsService - Starting up...")
        # Start Flask in a separate thread
        flask_thread = threading.Thread(target=run_signer)
        flask_thread.start()

        # Keep the service running
        while self.is_running:
            time.sleep(5)

    def SvcStop(self):
        servicemanager.LogInfoMsg("UltraSignerWindowsService - Shutting down...")
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self.is_running = False

if __name__ == '__main__':
    win32serviceutil.HandleCommandLine(UltraSignerSvc)
import sys

import gui.guilayer as guilayer
import util.misc_handler as misc
import util.icmp_util as icmputil


if __name__=="__main__":
    qtapp = guilayer.Cust_QApplication(sys.argv)
    qtmain_winow = guilayer.Cust_QMainWindow()
    #qtmain_winow.icmptunnel_client = icmputil.IcmpTunnel()

    
    qtmain_winow.update_userip(" " + misc.get_local_ip())


    qtmain_winow.show()
    sys.exit(qtapp.exec())
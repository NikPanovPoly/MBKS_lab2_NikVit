#include "info_getter.h"


//void setMandatoryLevel(Ui::processenjoyerClass ui, HANDLE hPipe, DWORD dwWritten, int *err){
//        hPipe = CreateFile(TEXT("\\\\.\\pipe\\Pipe"), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
//        QString int_path = ui.lineEdit->text();
//        if (int_path.isEmpty() != 1) {
//            struct choice {
//                int UNTRUSTED; // 7
//                int LOW; // 9
//                int MEDIUM; // 10
//                int HIGH; // 8
//                int SYS; // 6
//            } int_lvl = {
//                ui.radioButton_7->isChecked(),
//                ui.radioButton_9->isChecked(),
//                ui.radioButton_10->isChecked(),
//                ui.radioButton_8->isChecked(),
//                ui.radioButton_8->isChecked(),
//            };
//            WCHAR* data = new WCHAR[int_path.length() + 6];
//            std::wstring wideStr = int_path.toStdWString();
//            const wchar_t* wcharStr = wideStr.c_str();
//            data[0] = '3'; data[1] = ' ';
//
//            if (int_lvl.UNTRUSTED) {
//
//            }
//            else if (int_lvl.LOW) {
//                data[3] = 'L';data[4] = 'o';data[5] = 'w';
//                wcscpy(&data[6], wcharStr);
//                WriteFile(hPipe, &data, sizeof(data), &dwWritten, NULL);
//            }
//            else if (int_lvl.MEDIUM) {
//                data[3] = 'M'; data[4] = 'e'; data[5] = 'd'; data[6] = 'i'; data[7] = 'u'; data[8] = 'm';
//                wcscpy(&data[9], wcharStr);
//                WriteFile(hPipe, &data, sizeof(data), &dwWritten, NULL);
//            }
//            else if (int_lvl.HIGH) {
//                data[3] = 'H'; data[4] = 'i'; data[5] = 'g'; data[6] = 'h';
//                wcscpy(&data[7], wcharStr);
//                WriteFile(hPipe, &data, sizeof(data), &dwWritten, NULL);
//            }
//            else if (int_lvl.SYS) {
//
//            }
//            else{
//                *err = 1337;
//            }
//        }
//        else {
//            *err = 228;
//        }
//
//        if (*err != 0) {
//            switch (*err) {
//            case 228:
//                QMessageBox::information(this, "ERROR", "NO FILE");
//                break;
//            case 1337:
//                //QMessageBox::information(this, "ERROR", "FUCK");
//                break;
//            default:
//                //QMessageBox::information(this, "ERROR", "WTF");
//                break;
//            }
//        }
//}
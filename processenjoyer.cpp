
#include "info_getter.h"

processenjoyer::processenjoyer(QWidget* parent)
    : QMainWindow(parent)
{

    ui.setupUi(this);
    QLocale curLocale(QLocale("ru_RU"));
    QLocale::setDefault(curLocale);
    setlocale(LC_ALL, "");

    wchar_t buffer[1024];

    DWORD dwRead;
    DWORD dwWritten;
    DWORD dwTmp = 0;
    LPCWSTR message = { 0 };
    HANDLE hPipe;
    process proc_data = { 0 };

    int err = 0;

    hPipe = CreateFile(TEXT("\\\\.\\pipe\\Pipe"), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    this->pipePtr = hPipe;

    if (hPipe != INVALID_HANDLE_VALUE){

        updateTable(ui, hPipe, dwWritten, proc_data, dwRead);

        char done[5];
        if (ReadFile(hPipe, done, sizeof(done), &dwRead, NULL) == FALSE) {
            QMessageBox::information(this, "Error", "Error recieving final info");
        };

        connect(ui.submButton, &QPushButton::clicked, this, [&]() {
            emit setMandatoryLevel(ui, hPipe, dwWritten);
        });

        connect(ui.submButton_2, &QPushButton::clicked, this, [&]() {
            emit setProcessIntegrity(ui, hPipe, dwWritten);
        });

        connect(ui.tstMandatory, &QPushButton::clicked, this, [&]() {
            emit getMandatoryLevel(ui, hPipe, dwWritten);
         });
        connect(ui.tstIntegrity, &QPushButton::clicked, this, [&]() {
            emit getProcessIntegrity(ui, hPipe, dwWritten);
        });
        
        connect(ui.toolButton, &QPushButton::clicked, this, [&]() {
            emit reloadTable(ui, hPipe, dwWritten, proc_data, dwRead);
        });
    }
    
}

void processenjoyer::reloadTable(Ui::processenjoyerClass ui, HANDLE hPipe, DWORD dwWritten, process proc_data, DWORD dwRead) {
    hPipe = this->pipePtr;
    ui.tableWidget->setRowCount(0);
    WCHAR data[5] = { 0 };
    data[0] = '0'; data[1] = '\0';
    WriteFile(hPipe, data, sizeof(data), &dwWritten, NULL);
    updateTable(ui, hPipe, dwWritten, proc_data, dwRead);
   
}

void processenjoyer::updateTable(Ui::processenjoyerClass ui, HANDLE hPipe, DWORD dwWritten, process proc_data, DWORD dwRead) {
    hPipe = this->pipePtr;
    char* wcharConverter;
    int err = 0;
    for (size_t row = 0; ; row++) {
        int col = 0;
        if (ReadFile(hPipe, &proc_data, sizeof(proc_data), &dwRead, NULL) != FALSE)
        {
            WriteFile(hPipe, &proc_data, sizeof(proc_data), &dwWritten, NULL);
        }
        else {
            break;
        }
        if (proc_data.PID == 0) {
            break;
        }
        wchar_t nil = { '\0' };

        QByteArray encodedString;
        auto toSysEnc = QStringDecoder(QStringDecoder::System);

        if (err != 1) {
            ui.tableWidget->insertRow(ui.tableWidget->rowCount());

            ui.tableWidget->setItem(row, col++,
                new QTableWidgetItem(std::to_string(proc_data.PID).c_str()));

            wcharConverter = new char[sizeof(proc_data.processName)];
            wcstombs(wcharConverter, proc_data.processName, sizeof(proc_data.processName));
            encodedString = wcharConverter;
            QString string = toSysEnc(encodedString);
            ui.tableWidget->setItem(row, col++,
                new QTableWidgetItem(
                    string
                )
            );
            delete[] wcharConverter;

            wcharConverter = new char[sizeof(proc_data.pathProcessExe)];
            wcstombs(wcharConverter, proc_data.pathProcessExe, sizeof(proc_data.pathProcessExe));
            ui.tableWidget->setItem(row, col++,
                new QTableWidgetItem(
                    wcharConverter
                )
            );
            delete[] wcharConverter;

            wcharConverter = new char[sizeof(proc_data.processOwner)];
            wcstombs(wcharConverter, proc_data.processOwner, sizeof(proc_data.processOwner));
            encodedString = wcharConverter;
            string = toSysEnc(encodedString);
            ui.tableWidget->setItem(row, col++,
                new QTableWidgetItem(
                    string
                )
            );
            delete[] wcharConverter;

            wcharConverter = new char[sizeof(proc_data.SID)];
            wcstombs(wcharConverter, proc_data.SID, sizeof(proc_data.SID));
            ui.tableWidget->setItem(row, col++,
                new QTableWidgetItem(
                    wcharConverter
                )
            );
            delete[] wcharConverter;

            wcharConverter = new char[sizeof(proc_data.procType)];
            wcstombs(wcharConverter, proc_data.procType, sizeof(proc_data.procType));
            ui.tableWidget->setItem(row, col++,
                new QTableWidgetItem(
                    wcharConverter
                )
            );
            delete[] wcharConverter;

            wcharConverter = new char[sizeof(proc_data.integrityLevel)];
            wcstombs(wcharConverter, proc_data.integrityLevel, sizeof(proc_data.integrityLevel));
            ui.tableWidget->setItem(row, col++,
                new QTableWidgetItem(
                    wcharConverter
                )
            );
            delete[] wcharConverter;

            wcharConverter = new char[sizeof(proc_data.procDescryption)];
            wcstombs(wcharConverter, proc_data.procDescryption, sizeof(proc_data.procDescryption));
            encodedString = wcharConverter;
            string = toSysEnc(encodedString);
            ui.tableWidget->setItem(row, col++,
                new QTableWidgetItem(
                    string
                )
            );
            delete[] wcharConverter;
            ui.tableWidget->setItem(row, col++,
                new QTableWidgetItem(std::to_string(proc_data.CLR).c_str())
            );
            ui.tableWidget->setItem(row, col++,
                new QTableWidgetItem(std::to_string(proc_data.ASLR).c_str())
            );
            ui.tableWidget->setItem(row, col++,
                new QTableWidgetItem(std::to_string(proc_data.DEP).c_str())
            );

            wcharConverter = new char[sizeof(proc_data.aslrDetails)];
            wcstombs(wcharConverter, proc_data.aslrDetails, sizeof(proc_data.aslrDetails));
            ui.tableWidget->setItem(row, col++,
                new QTableWidgetItem(
                    wcharConverter
                )
            );
            delete[] wcharConverter;

            wcharConverter = new char[sizeof(proc_data.depDetails)];
            wcstombs(wcharConverter, proc_data.depDetails, sizeof(proc_data.depDetails));
            ui.tableWidget->setItem(row, col++,
                new QTableWidgetItem(
                    wcharConverter
                )
            );
            delete[] wcharConverter;

            wcharConverter = new char[sizeof(proc_data.parentName)];
            wcstombs(wcharConverter, proc_data.parentName, sizeof(proc_data.parentName));
            ui.tableWidget->setItem(row, col++,
                new QTableWidgetItem(
                    wcharConverter
                )
            );
            delete[] wcharConverter;

            ui.tableWidget->setItem(row, col++,
                new QTableWidgetItem(std::to_string(proc_data.parentPID).c_str()));

            QPushButton* DLLButton = new QPushButton("DLL_LIST");
            ui.tableWidget->setCellWidget(row, col++,
                DLLButton
            );

            QDialog* DllDialog = new QDialog(this);
            QTableWidget* table = new QTableWidget(DllDialog);
            Ui_Dialog* DllUi = new Ui_Dialog;
            QHBoxLayout* layout = new QHBoxLayout(DllDialog);

            table->setFixedWidth(700);
            table->insertColumn(0);
            table->setHorizontalHeaderLabels({ "DLL NAME" });
            table->setColumnWidth(0, 600);

            int dll_col = 0;
            for (int dll_count = 0; ; dll_count++) {
                dll_col = 0;

                wchar_t symb = proc_data.processDllsName[dll_count][0];
                if (symb == nil) {
                    break;
                }
                table->insertRow(table->rowCount());

                wcharConverter = new char[sizeof(proc_data.processDllsName[dll_count])];
                wcstombs(wcharConverter, proc_data.processDllsName[dll_count], sizeof(proc_data.processDllsName[dll_count]));

                table->setItem(dll_count, dll_col++,
                    new QTableWidgetItem(
                        wcharConverter
                    )
                );
                delete[] wcharConverter;
            }
            setContentsMargins(20, 0, 0, 0);
            layout->addWidget(table, 0, Qt::AlignLeft);
            DllUi->setupUi(DllDialog);
            connect(DllUi->okButton, SIGNAL(clicked()), DllDialog, SLOT(close()));
            connect(DLLButton, SIGNAL(clicked()), DllDialog, SLOT(exec()));

        }
    }
}

void processenjoyer::setMandatoryLevel(Ui::processenjoyerClass ui, HANDLE hPipe, DWORD dwWritten) {
    hPipe = this->pipePtr;
    int err = 0;
    if (hPipe != INVALID_HANDLE_VALUE) {
        QString int_path = ui.lineEdit->text();
        if (int_path.isEmpty() != 1) {
            if (!std::filesystem::exists(int_path.toStdString())) {
                err = NO_SUCH_FILE;
            }
            struct choice {
                //int UNTRUSTED; // 7
                int LOW; // 9
                int MEDIUM; // 10
                int HIGH; // 8
                //int SYS; // 6
            } int_lvl = {
                ui.radioButton_9->isChecked(),
                ui.radioButton_10->isChecked(),
                ui.radioButton_8->isChecked(),
            };
            WCHAR data[100] = { 0 };

            std::wstring wideStr = int_path.toStdWString();
            const wchar_t* wcharStr = wideStr.c_str();
            data[0] = '3'; data[1] = ' ';

            if (int_lvl.LOW) {
                data[2] = 'L'; data[3] = 'o'; data[4] = 'w'; data[5] = ' ';
                wcscpy(&data[6], wcharStr);
                WriteFile(hPipe, data, sizeof(data), &dwWritten, NULL);
            }
            else if (int_lvl.MEDIUM) {
                data[2] = 'M'; data[3] = 'e'; data[4] = 'd'; data[5] = 'i'; data[6] = 'u'; data[7] = 'm';  data[8] = ' ';
                wcscpy(&data[9], wcharStr);
                WriteFile(hPipe, data, sizeof(data), &dwWritten, NULL);
            }
            else if (int_lvl.HIGH) {
                data[2] = 'H'; data[3] = 'i'; data[4] = 'g'; data[5] = 'h'; data[6] = ' ';
                wcscpy(&data[7], wcharStr);
                WriteFile(hPipe, data, sizeof(data), &dwWritten, NULL);
            }
            else {
                err = NOT_SELECTED;
            }
        }
        else {
            err = NO_FILE;
        }

        if (err != 0) {
            switch (err) {
            case NO_FILE:
                QMessageBox::information(this, "Error", "No such file");
                break;
            case NOT_SELECTED:
                QMessageBox::information(this, "Error", "No Mandatory level selected");
                break;
            case NO_SUCH_FILE:
                QMessageBox::information(this, "Error", "No such file found");
                break;
            default:
                QMessageBox::information(this, "Error", "Unknown error");
                break;
            }
        }
        else {
            QMessageBox::information(this, "Success", "Successfully changed level");
        }
    }
    else {
        QMessageBox::information(this, "Error", "Pipe problem");
    }
}

void processenjoyer::setProcessIntegrity(Ui::processenjoyerClass ui, HANDLE hPipe, DWORD dwWritten) {
    hPipe = this->pipePtr;
    int err = 0;
    if (hPipe != INVALID_HANDLE_VALUE) {
        WCHAR data[100] = { 0 };

        QString PID_value = ui.lineEdit_2->text();
        if (PID_value.isEmpty() != 1) {
            struct choice {
                int LOW; // 12
                int MEDIUM; // 13
                int HIGH; // 14
            } int_lvl = {
                ui.radioButton_12->isChecked(),
                ui.radioButton_13->isChecked(),
                ui.radioButton_14->isChecked(),
            };

            std::wstring wideStr = PID_value.toStdWString();
            const wchar_t* wcharStr = wideStr.c_str();
            data[0] = '1'; data[1] = ' ';

            if (int_lvl.LOW) {
                data[2] = 'L'; data[3] = 'o'; data[4] = 'w'; data[5] = ' ';
                wcscpy(&data[6], wcharStr);
                WriteFile(hPipe, data, sizeof(data), &dwWritten, NULL);
            }
            else if (int_lvl.MEDIUM) {
                data[2] = 'M'; data[3] = 'e'; data[4] = 'd'; data[5] = 'i'; data[6] = 'u'; data[7] = 'm';  data[8] = ' ';
                wcscpy(&data[9], wcharStr);
                WriteFile(hPipe, data, sizeof(data), &dwWritten, NULL);
            }
            else if (int_lvl.HIGH) {
                data[2] = 'H'; data[3] = 'i'; data[4] = 'g'; data[5] = 'h'; data[6] = ' ';
                wcscpy(&data[7], wcharStr);
                WriteFile(hPipe, data, sizeof(data), &dwWritten, NULL);
            }
            else {
                err = NOT_SELECTED;
            }
        }
        else {
            err = NO_PID;
        }

        if (err != 0) {
            switch (err) {
            case NO_PID:
                QMessageBox::information(this, "Error", "No such process");
                break;
            case NOT_SELECTED:
                QMessageBox::information(this, "Error", "No Integrity level selected");
                break;
            default:
                QMessageBox::information(this, "Error", "Unknown error");
                break;
            }
        }
        else {
            QMessageBox::information(this, "Success", "Successfully changed level");
            for (int row = 0; row < ui.tableWidget->rowCount(); ++row) {
                QTableWidgetItem* pidItem = ui.tableWidget->item(row, 0);
                QString pidVal = pidItem->text();
                if (PID_value == pidVal) {
                    QTableWidgetItem* dataInt;
                    switch (data[2]) {
                    case 'H':
                        dataInt = new QTableWidgetItem("High");
                        break;
                    case 'M':
                        dataInt = new QTableWidgetItem("Medium");
                        break;
                    case 'L':
                        dataInt = new QTableWidgetItem("Low");
                        break;
                    }
                    ui.tableWidget->setItem(row, 6, dataInt);
                }
            }
        }
    }
    else {
        QMessageBox::information(this, "Error", "Pipe problem");
    }
}

void processenjoyer::getProcessIntegrity(Ui::processenjoyerClass ui, HANDLE hPipe, DWORD dwWritten) {
    hPipe = this->pipePtr;
    DWORD dwRead;

    if (hPipe != INVALID_HANDLE_VALUE) {
        QString PID_value = ui.lineEdit_2->text();
        if (PID_value.isEmpty() != 1) {
            for (int row = 0; row < ui.tableWidget->rowCount(); ++row) {
                QTableWidgetItem* pidItem = ui.tableWidget->item(row, 0);
                QString pidVal = pidItem->text();
                if (PID_value == pidVal) {
                    QTableWidgetItem* integrityItem = ui.tableWidget->item(row, 6);
                    QMessageBox::information(this, "Success", integrityItem->text());
                }
            }
        }
    }
}

void processenjoyer::getMandatoryLevel(Ui::processenjoyerClass ui, HANDLE hPipe, DWORD dwWritten) {
    hPipe = this->pipePtr;
    DWORD dwRead;

    if (hPipe != INVALID_HANDLE_VALUE) {
        QString int_path = ui.lineEdit->text();
        if (int_path.isEmpty() != 1) {
            WCHAR data[100] = { 0 };
            data[0] = '2'; data[1] = ' ';
            std::wstring wideStr = int_path.toStdWString();
            const wchar_t* wcharStr = wideStr.c_str();
            wcscpy(&data[2], wcharStr);

            WriteFile(hPipe, data, sizeof(data), &dwWritten, NULL);
            ReadFile(hPipe, &data, sizeof(data), &dwRead, NULL);
            QString success = "File mandatory is ";
            success += data;
            QMessageBox::information(this, "Success", success);

        } 
    }
}

processenjoyer::~processenjoyer()
{

}

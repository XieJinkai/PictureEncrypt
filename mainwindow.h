#pragma once

#include <QByteArray>
#include <QMainWindow>
#include <QSharedPointer>
#include <QVector>
#include <QImage>

class QProgressDialog;
class QAtomicInt;

namespace Ui
{
class MainWindow;
}

class MainWindow final : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow() override;

    struct ImageItem
    {
        QString filePath;
        QString fileName;
        QByteArray plainBytes;
        QImage image;
    };

private slots:
    void onImportImage();
    void onBrowseOutput();
    void onExport();
    void onDecryptPreview();
    void onListContextMenu(const QPoint &pos);
    void onExportOneDone(int successDelta);
    void onExportTaskDone();
    void onExportCanceled();

private:
    void reloadPreviewList();

    Ui::MainWindow *ui{};

    QVector<ImageItem> m_items;

    QProgressDialog *m_exportProgressDialog{};
    QSharedPointer<QAtomicInt> m_exportCancelFlag;
    QSharedPointer<QVector<ImageItem>> m_exportSnapshotItems;
    QString m_exportOutputDirPath;
    QString m_exportOutputSuffix;
    QString m_exportKey;
    int m_exportTotal = 0;
    int m_exportDone = 0;
    int m_exportSuccess = 0;
    int m_exportTasksRemaining = 0;
};

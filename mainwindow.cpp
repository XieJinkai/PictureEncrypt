#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <algorithm>
#include <QByteArray>
#include <QAtomicInt>
#include <QCryptographicHash>
#include <QDataStream>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QImage>
#include <QImageReader>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QListView>
#include <QMenu>
#include <QMessageBox>
#include <QPixmap>
#include <QProgressDialog>
#include <QPushButton>
#include <QRandomGenerator>
#include <QBuffer>
#include <QThreadPool>
#include <QRunnable>
#include <QVBoxLayout>
#include <QWidget>

namespace
{
constexpr quint32 kMagic = 0x31505859;
constexpr quint16 kVersion = 1;
constexpr quint16 kAlgoStreamSha256 = 1;
const QString kDefaultOutputSuffix = QStringLiteral(".pct");

QByteArray randomBytes(int size)
{
    QByteArray out;
    out.resize(size);
    auto *rng = QRandomGenerator::system();
    for (int i = 0; i < size; i += 4)
    {
        const quint32 v = rng->generate();
        const int remaining = qMin(4, size - i);
        for (int j = 0; j < remaining; ++j)
        {
            out[i + j] = static_cast<char>((v >> (j * 8)) & 0xFF);
        }
    }
    return out;
}

QByteArray xorWithDerivedStream(const QByteArray &input, const QByteArray &keyUtf8, const QByteArray &salt)
{
    QByteArray output = input;
    output.detach();

    if (keyUtf8.isEmpty())
    {
        return {};
    }

    quint32 counter = 0;
    int offset = 0;

    while (offset < output.size())
    {
        QByteArray seed;
        seed.reserve(keyUtf8.size() + salt.size() + 4);
        seed.append(keyUtf8);
        seed.append(salt);
        seed.append(static_cast<char>(counter & 0xFF));
        seed.append(static_cast<char>((counter >> 8) & 0xFF));
        seed.append(static_cast<char>((counter >> 16) & 0xFF));
        seed.append(static_cast<char>((counter >> 24) & 0xFF));

        const QByteArray digest = QCryptographicHash::hash(seed, QCryptographicHash::Sha256);
        const int chunk = qMin(digest.size(), output.size() - offset);
        for (int i = 0; i < chunk; ++i)
        {
            output[offset + i] = static_cast<char>(static_cast<unsigned char>(output[offset + i]) ^ static_cast<unsigned char>(digest[i]));
        }

        offset += chunk;
        ++counter;
    }

    return output;
}

bool normalizeOutputSuffix(const QString &input, QString *outSuffix, QString *outError)
{
    QString s = input.trimmed();
    if (s.isEmpty())
    {
        s = kDefaultOutputSuffix;
    }
    if (!s.startsWith('.'))
    {
        s.prepend('.');
    }
    if (s.size() < 2)
    {
        if (outError)
        {
            *outError = QStringLiteral("输出后缀不合法");
        }
        return false;
    }

    const QString invalidChars = QStringLiteral("\\/:*?\"<>|");
    for (const QChar ch : invalidChars)
    {
        if (s.contains(ch))
        {
            if (outError)
            {
                *outError = QStringLiteral("输出后缀包含非法字符：%1").arg(ch);
            }
            return false;
        }
    }

    if (outSuffix)
    {
        *outSuffix = s;
    }
    return true;
}

QByteArray buildYxpBlob(const QByteArray &plainBytes, const QString &originalFileName, const QString &key)
{
    const QByteArray keyUtf8 = key.toUtf8();
    if (plainBytes.isEmpty() || keyUtf8.isEmpty())
    {
        return {};
    }

    const QByteArray nameUtf8 = originalFileName.toUtf8();
    const QByteArray salt = randomBytes(16);
    const QByteArray sha256Plain = QCryptographicHash::hash(plainBytes, QCryptographicHash::Sha256);
    const QByteArray cipher = xorWithDerivedStream(plainBytes, keyUtf8, salt);
    if (cipher.isEmpty())
    {
        return {};
    }

    QByteArray blob;
    QDataStream out(&blob, QIODevice::WriteOnly);
    out.setByteOrder(QDataStream::LittleEndian);
    out.setVersion(QDataStream::Qt_6_0);

    out << kMagic;
    out << kVersion;
    out << kAlgoStreamSha256;
    out << static_cast<quint16>(salt.size());
    out << static_cast<quint16>(0);
    out << static_cast<quint64>(plainBytes.size());
    out << static_cast<quint16>(nameUtf8.size());
    out << static_cast<quint16>(sha256Plain.size());

    out.writeRawData(nameUtf8.constData(), nameUtf8.size());
    out.writeRawData(salt.constData(), salt.size());
    out.writeRawData(sha256Plain.constData(), sha256Plain.size());
    out.writeRawData(cipher.constData(), cipher.size());

    if (out.status() != QDataStream::Ok)
    {
        return {};
    }

    return blob;
}

struct ParsedYxp
{
    QString name;
    QByteArray salt;
    QByteArray sha256Plain;
    QByteArray cipher;
    quint64 originalSize = 0;
};

bool parseYxpBlob(const QByteArray &blob, ParsedYxp &outParsed)
{
    QBuffer buffer;
    buffer.setData(blob);
    if (!buffer.open(QIODevice::ReadOnly))
    {
        return false;
    }

    QDataStream in(&buffer);
    in.setByteOrder(QDataStream::LittleEndian);
    in.setVersion(QDataStream::Qt_6_0);

    quint32 magic = 0;
    quint16 version = 0;
    quint16 algo = 0;
    quint16 saltLen = 0;
    quint16 reserved = 0;
    quint64 originalSize = 0;
    quint16 nameLen = 0;
    quint16 shaLen = 0;

    in >> magic >> version >> algo >> saltLen >> reserved >> originalSize >> nameLen >> shaLen;
    if (in.status() != QDataStream::Ok)
    {
        return false;
    }
    if (magic != kMagic || version != kVersion || algo != kAlgoStreamSha256 || reserved != 0)
    {
        return false;
    }
    if (saltLen == 0 || shaLen == 0)
    {
        return false;
    }

    QByteArray nameUtf8;
    nameUtf8.resize(nameLen);
    if (nameLen > 0 && in.readRawData(nameUtf8.data(), nameLen) != nameLen)
    {
        return false;
    }

    QByteArray salt;
    salt.resize(saltLen);
    if (in.readRawData(salt.data(), saltLen) != saltLen)
    {
        return false;
    }

    QByteArray sha;
    sha.resize(shaLen);
    if (in.readRawData(sha.data(), shaLen) != shaLen)
    {
        return false;
    }

    const int headerBytes = 24;
    const int payloadOffset = headerBytes + nameLen + saltLen + shaLen;
    if (payloadOffset < 0 || payloadOffset > blob.size())
    {
        return false;
    }

    const QByteArray cipher = blob.mid(payloadOffset);
    if (cipher.isEmpty())
    {
        return false;
    }

    outParsed.name = QString::fromUtf8(nameUtf8);
    outParsed.salt = salt;
    outParsed.sha256Plain = sha;
    outParsed.cipher = cipher;
    outParsed.originalSize = originalSize;
    return true;
}

QByteArray decryptYxpToPlain(const QByteArray &blob, const QString &key, QString *outName, QString *outError)
{
    ParsedYxp parsed;
    if (!parseYxpBlob(blob, parsed))
    {
        if (outError)
        {
            *outError = QStringLiteral("文件格式不正确或已损坏");
        }
        return {};
    }
    if (outName)
    {
        *outName = parsed.name;
    }

    const QByteArray keyUtf8 = key.toUtf8();
    if (keyUtf8.isEmpty())
    {
        if (outError)
        {
            *outError = QStringLiteral("密钥不能为空");
        }
        return {};
    }

    const QByteArray plain = xorWithDerivedStream(parsed.cipher, keyUtf8, parsed.salt);
    if (plain.isEmpty())
    {
        if (outError)
        {
            *outError = QStringLiteral("解密失败");
        }
        return {};
    }

    const QByteArray sha = QCryptographicHash::hash(plain, QCryptographicHash::Sha256);
    if (sha != parsed.sha256Plain)
    {
        if (outError)
        {
            *outError = QStringLiteral("密钥错误或文件已被篡改");
        }
        return {};
    }

    return plain;
}

bool writeBinaryFile(const QString &path, const QByteArray &bytes, QString *outError)
{
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate))
    {
        if (outError)
        {
            *outError = QStringLiteral("无法写入文件：%1").arg(path);
        }
        return false;
    }
    if (f.write(bytes) != bytes.size())
    {
        if (outError)
        {
            *outError = QStringLiteral("写入失败：%1").arg(path);
        }
        return false;
    }
    return true;
}

class ExportTask final : public QRunnable
{
public:
    ExportTask(MainWindow *window,
               QSharedPointer<QAtomicInt> cancelFlag,
               QSharedPointer<QVector<MainWindow::ImageItem>> items,
               int beginIndex,
               int endIndex,
               QString outputDirPath,
               QString outputSuffix,
               QString key)
        : m_window(window),
          m_cancelFlag(std::move(cancelFlag)),
          m_items(std::move(items)),
          m_beginIndex(beginIndex),
          m_endIndex(endIndex),
          m_outputDirPath(std::move(outputDirPath)),
          m_outputSuffix(std::move(outputSuffix)),
          m_key(std::move(key))
    {
        setAutoDelete(true);
    }

    void run() override
    {
        if (!m_window || !m_cancelFlag || !m_items)
        {
            return;
        }

        QDir outDir(m_outputDirPath);

        const int safeBegin = qMax(0, m_beginIndex);
        const int safeEnd = qMin(m_endIndex, m_items->size());

        for (int i = safeBegin; i < safeEnd; ++i)
        {
            if (m_cancelFlag->loadRelaxed() != 0)
            {
                break;
            }

            const auto &item = (*m_items)[i];
            const QByteArray blob = buildYxpBlob(item.plainBytes, item.fileName, m_key);
            bool ok = false;
            if (!blob.isEmpty())
            {
                const QFileInfo info(item.fileName);
                const QString baseName = info.completeBaseName();
                const QString outPath = outDir.absoluteFilePath(baseName + m_outputSuffix);
                QString err;
                ok = writeBinaryFile(outPath, blob, &err);
            }

            if (m_window)
            {
                QMetaObject::invokeMethod(m_window, "onExportOneDone", Qt::QueuedConnection, Q_ARG(int, ok ? 1 : 0));
            }
        }

        if (m_window)
        {
            QMetaObject::invokeMethod(m_window, "onExportTaskDone", Qt::QueuedConnection);
        }
    }

private:
    QPointer<MainWindow> m_window;
    QSharedPointer<QAtomicInt> m_cancelFlag;
    QSharedPointer<QVector<MainWindow::ImageItem>> m_items;
    int m_beginIndex = 0;
    int m_endIndex = 0;
    QString m_outputDirPath;
    QString m_outputSuffix;
    QString m_key;
};
} // namespace

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    ui->m_keyEdit->setEchoMode(QLineEdit::Password);
    ui->m_keyEdit->setPlaceholderText(QStringLiteral("请输入密钥（加密/解密共用）"));

    ui->m_outputSuffixEdit->setText(kDefaultOutputSuffix);
    ui->m_outputSuffixEdit->setPlaceholderText(kDefaultOutputSuffix);

    ui->m_infoLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);

    ui->m_listWidget->setViewMode(QListView::IconMode);
    ui->m_listWidget->setFlow(QListView::LeftToRight);
    ui->m_listWidget->setWrapping(true);
    ui->m_listWidget->setResizeMode(QListWidget::Adjust);
    const QSize cellSize(160, 180);
    ui->m_listWidget->setIconSize(QSize(128, 128));
    ui->m_listWidget->setGridSize(cellSize);
    const int spacing = 8;
    ui->m_listWidget->setSpacing(spacing);
    ui->m_listWidget->setSelectionMode(QAbstractItemView::ExtendedSelection);
    ui->m_listWidget->setSelectionBehavior(QAbstractItemView::SelectItems);
    ui->m_listWidget->setContextMenuPolicy(Qt::CustomContextMenu);

    setWindowTitle(QStringLiteral("PictureEncrypt"));
    resize(900, 650);

    connect(ui->m_importButton, &QPushButton::clicked, this, &MainWindow::onImportImage);
    connect(ui->m_browseOutputButton, &QPushButton::clicked, this, &MainWindow::onBrowseOutput);
    connect(ui->m_exportButton, &QPushButton::clicked, this, &MainWindow::onExport);
    connect(ui->m_decryptPreviewButton, &QPushButton::clicked, this, &MainWindow::onDecryptPreview);
    connect(ui->m_listWidget, &QListWidget::customContextMenuRequested, this, &MainWindow::onListContextMenu);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::reloadPreviewList()
{
    ui->m_listWidget->clear();

    const QSize iconSize = ui->m_listWidget->iconSize();

    for (const auto &item : m_items)
    {
        auto *witem = new QListWidgetItem();
        witem->setText(item.fileName);
        if (!item.image.isNull())
        {
            QPixmap pix = QPixmap::fromImage(item.image);
            if (!iconSize.isEmpty())
            {
                pix = pix.scaled(iconSize, Qt::KeepAspectRatio, Qt::SmoothTransformation);
            }
            witem->setIcon(QIcon(pix));
        }
        ui->m_listWidget->addItem(witem);
    }
}

void MainWindow::onListContextMenu(const QPoint &pos)
{
    if (m_items.isEmpty())
    {
        return;
    }

    const QList<QListWidgetItem *> selectedItems = ui->m_listWidget->selectedItems();
    if (selectedItems.isEmpty())
    {
        return;
    }

    QMenu menu(this);
    QAction *removeAction = menu.addAction(QStringLiteral("移除选中项"));
    const QPoint globalPos = ui->m_listWidget->viewport()->mapToGlobal(pos);
    QAction *chosen = menu.exec(globalPos);
    if (chosen == removeAction)
    {
        QVector<int> rows;
        rows.reserve(selectedItems.size());
        for (QListWidgetItem *item : selectedItems)
        {
            const int row = ui->m_listWidget->row(item);
            if (row >= 0 && row < m_items.size())
            {
                rows.append(row);
            }
        }
        std::sort(rows.begin(), rows.end());
        rows.erase(std::unique(rows.begin(), rows.end()), rows.end());
        for (int i = rows.size() - 1; i >= 0; --i)
        {
            const int row = rows[i];
            m_items.removeAt(row);
            delete ui->m_listWidget->takeItem(row);
        }
        ui->m_infoLabel->setText(QStringLiteral("剩余图片数量：%1").arg(m_items.size()));
    }
}

void MainWindow::onImportImage()
{
    const QString dirPath = QFileDialog::getExistingDirectory(
        this,
        QStringLiteral("选择图片所在文件夹"),
        QString());
    if (dirPath.isEmpty())
    {
        return;
    }

    QDir dir(dirPath);
    QStringList filters;
    filters << QStringLiteral("*.png")
            << QStringLiteral("*.jpg")
            << QStringLiteral("*.jpeg")
            << QStringLiteral("*.bmp")
            << QStringLiteral("*.webp")
            << QStringLiteral("*.gif");

    const QFileInfoList infos = dir.entryInfoList(filters, QDir::Files | QDir::NoSymLinks | QDir::Readable);
    if (infos.isEmpty())
    {
        QMessageBox::warning(this, QStringLiteral("提示"), QStringLiteral("该文件夹中没有可识别的图片"));
        return;
    }

    m_items.clear();

    for (const QFileInfo &info : infos)
    {
        QFile f(info.absoluteFilePath());
        if (!f.open(QIODevice::ReadOnly))
        {
            continue;
        }
        const QByteArray bytes = f.readAll();
        if (bytes.isEmpty())
        {
            continue;
        }

        QImageReader reader(info.absoluteFilePath());
        reader.setAutoTransform(true);
        const QImage img = reader.read();
        if (img.isNull())
        {
            continue;
        }

        ImageItem item;
        item.filePath = info.absoluteFilePath();
        item.fileName = info.fileName();
        item.plainBytes = bytes;
        item.image = img;
        m_items.push_back(item);
    }

    if (m_items.isEmpty())
    {
        QMessageBox::warning(this, QStringLiteral("提示"), QStringLiteral("该文件夹中的图片无法读取或全部无效"));
        return;
    }

    reloadPreviewList();

    ui->m_infoLabel->setText(QStringLiteral("已导入文件夹：%1，图片数量：%2")
                                 .arg(dirPath)
                                 .arg(m_items.size()));
}

void MainWindow::onBrowseOutput()
{
    const QString path = QFileDialog::getExistingDirectory(
        this,
        QStringLiteral("选择输出文件夹"),
        QString());
    if (!path.isEmpty())
    {
        ui->m_outputPathEdit->setText(path);
    }
}

void MainWindow::onExport()
{
    if (m_items.isEmpty())
    {
        QMessageBox::warning(this, QStringLiteral("提示"), QStringLiteral("请先导入图片文件夹"));
        return;
    }
    if (m_exportProgressDialog)
    {
        return;
    }
    const QString key = ui->m_keyEdit->text();
    if (key.isEmpty())
    {
        QMessageBox::warning(this, QStringLiteral("提示"), QStringLiteral("密钥不能为空"));
        return;
    }

    const QString outputDirPath = ui->m_outputPathEdit->text().trimmed();
    if (outputDirPath.isEmpty())
    {
        QMessageBox::warning(this, QStringLiteral("提示"), QStringLiteral("请选择输出文件夹"));
        return;
    }

    QString outputSuffix;
    QString suffixErr;
    if (!normalizeOutputSuffix(ui->m_outputSuffixEdit ? ui->m_outputSuffixEdit->text() : QString(), &outputSuffix, &suffixErr))
    {
        QMessageBox::warning(this, QStringLiteral("提示"), suffixErr);
        return;
    }

    QDir outDir(outputDirPath);
    if (!outDir.exists())
    {
        if (!outDir.mkpath(QStringLiteral(".")))
        {
            QMessageBox::critical(this, QStringLiteral("错误"), QStringLiteral("无法创建输出文件夹"));
            return;
        }
    }

    m_exportOutputDirPath = outputDirPath;
    m_exportOutputSuffix = outputSuffix;
    m_exportKey = key;
    m_exportTotal = m_items.size();
    m_exportDone = 0;
    m_exportSuccess = 0;
    m_exportTasksRemaining = 0;
    m_exportCancelFlag = QSharedPointer<QAtomicInt>::create(0);
    m_exportSnapshotItems = QSharedPointer<QVector<ImageItem>>::create(m_items);

    m_exportProgressDialog = new QProgressDialog(QStringLiteral("正在导出..."),
                                                 QStringLiteral("取消"),
                                                 0,
                                                 m_exportTotal,
                                                 this);
    m_exportProgressDialog->setWindowTitle(QStringLiteral("导出进度"));
    m_exportProgressDialog->setWindowModality(Qt::ApplicationModal);
    m_exportProgressDialog->setAutoClose(false);
    m_exportProgressDialog->setAutoReset(false);
    m_exportProgressDialog->setMinimumDuration(0);
    m_exportProgressDialog->setValue(0);
    m_exportProgressDialog->show();
    connect(m_exportProgressDialog, &QProgressDialog::canceled, this, &MainWindow::onExportCanceled);

    ui->m_importButton->setEnabled(false);
    ui->m_browseOutputButton->setEnabled(false);
    ui->m_exportButton->setEnabled(false);
    ui->m_decryptPreviewButton->setEnabled(false);

    const int chunkSize = 3;
    const int taskCount = (m_exportTotal + chunkSize - 1) / chunkSize;
    m_exportTasksRemaining = taskCount;

    for (int t = 0; t < taskCount; ++t)
    {
        const int beginIndex = t * chunkSize;
        const int endIndex = qMin(beginIndex + chunkSize, m_exportTotal);
        auto *task = new ExportTask(this,
                                    m_exportCancelFlag,
                                    m_exportSnapshotItems,
                                    beginIndex,
                                    endIndex,
                                    m_exportOutputDirPath,
                                    m_exportOutputSuffix,
                                    m_exportKey);
        QThreadPool::globalInstance()->start(task);
    }
}

void MainWindow::onExportOneDone(int successDelta)
{
    if (!m_exportProgressDialog)
    {
        return;
    }

    ++m_exportDone;
    if (successDelta > 0)
    {
        m_exportSuccess += successDelta;
    }

    m_exportProgressDialog->setValue(m_exportDone);
    m_exportProgressDialog->setLabelText(QStringLiteral("正在导出：%1 / %2").arg(m_exportDone).arg(m_exportTotal));
}

void MainWindow::onExportTaskDone()
{
    if (!m_exportProgressDialog)
    {
        return;
    }

    --m_exportTasksRemaining;
    if (m_exportTasksRemaining > 0)
    {
        return;
    }

    const bool canceled = (m_exportCancelFlag && m_exportCancelFlag->loadRelaxed() != 0);

    m_exportProgressDialog->close();
    m_exportProgressDialog->deleteLater();
    m_exportProgressDialog = nullptr;

    ui->m_importButton->setEnabled(true);
    ui->m_browseOutputButton->setEnabled(true);
    ui->m_exportButton->setEnabled(true);
    ui->m_decryptPreviewButton->setEnabled(true);

    if (canceled)
    {
        QMessageBox::information(this,
                                 QStringLiteral("已取消"),
                                 QStringLiteral("已导出：%1 / %2，成功：%3")
                                     .arg(m_exportDone)
                                     .arg(m_exportTotal)
                                     .arg(m_exportSuccess));
        return;
    }

    if (m_exportSuccess == 0)
    {
        QMessageBox::critical(this, QStringLiteral("错误"), QStringLiteral("所有图片加密失败"));
        return;
    }

    QMessageBox::information(this,
                             QStringLiteral("完成"),
                             QStringLiteral("已导出加密文件数量：%1，输出目录：%2")
                                 .arg(m_exportSuccess)
                                 .arg(m_exportOutputDirPath));
}

void MainWindow::onExportCanceled()
{
    if (!m_exportCancelFlag || !m_exportProgressDialog)
    {
        return;
    }
    m_exportCancelFlag->storeRelaxed(1);
    m_exportProgressDialog->setLabelText(QStringLiteral("正在取消..."));
}

void MainWindow::onDecryptPreview()
{
    QString outputSuffix;
    QString suffixErr;
    if (!normalizeOutputSuffix(ui->m_outputSuffixEdit ? ui->m_outputSuffixEdit->text() : QString(), &outputSuffix, &suffixErr))
    {
        outputSuffix = kDefaultOutputSuffix;
    }
    const QString filter = QStringLiteral("加密文件 (*%1);;All Files (*.*)").arg(outputSuffix);
    const QString path = QFileDialog::getOpenFileName(
        this,
        QStringLiteral("选择加密文件"),
        QString(),
        filter);
    if (path.isEmpty())
    {
        return;
    }

    QFile f(path);
    if (!f.open(QIODevice::ReadOnly))
    {
        QMessageBox::critical(this, QStringLiteral("错误"), QStringLiteral("无法读取文件：%1").arg(path));
        return;
    }
    const QByteArray blob = f.readAll();
    if (blob.isEmpty())
    {
        QMessageBox::critical(this, QStringLiteral("错误"), QStringLiteral("文件为空或读取失败"));
        return;
    }

    QString outName;
    QString err;
    const QByteArray plain = decryptYxpToPlain(blob, ui->m_keyEdit->text(), &outName, &err);
    if (plain.isEmpty())
    {
        QMessageBox::critical(this, QStringLiteral("错误"), err);
        return;
    }

    QImage img;
    if (!img.loadFromData(plain))
    {
        QMessageBox::critical(this, QStringLiteral("错误"), QStringLiteral("解密成功但无法解析为图片"));
        return;
    }

    m_items.clear();

    ImageItem item;
    item.filePath = path;
    item.fileName = outName;
    item.plainBytes = plain;
    item.image = img;
    m_items.push_back(item);

    reloadPreviewList();

    ui->m_infoLabel->setText(QStringLiteral("解密预览：%1，大小：%2 字节")
                                 .arg(outName, QString::number(plain.size())));
}

﻿#ifndef DIALOG_H
#define DIALOG_H

#include <QDialog>
#include <QtWebSockets/qwebsocket.h>
#include <memory>
#include <QSqlDatabase>
#include <QtXml/QDomElement>
#include "proxydialog.h"

namespace Ui {
class Dialog;
}

class Dialog : public QDialog
{
    Q_OBJECT

public:
    explicit Dialog(QWidget *parent = 0);
    ~Dialog();

private slots:
	void OnConnected();
	void OnDisconnect();
	void onMessageReceived(const QString& message);


    void on_login_clicked();
    void on_register_2_clicked();

    void on_addcontact_clicked();


    void on_send_clicked();

	void OutputAutoScroll();

    void on_contactlists_customContextMenuRequested(const QPoint &pos);

	void on_delete_contact();
	void on_create_group();
	void on_modify_group_name();
	void on_leave_group();


    void on_setproxy_clicked();

    void on_setserver_clicked();

private:
	//处理websocket 回包
	void HandleLoginResponse(const QString& message, const QJsonObject& root);
	void HandleSyncContact(const QString& message, const QDomElement& root);
	void HandleHD(const QString& message, const QDomElement& root);
	void HandleDefault(const QString& message, const QDomElement& root);
	void HandleSync(const QString& message, const QJsonObject& root);
	void HandleCreateGroup(const QString& message, const QDomElement& root);
	void HandleLeaveGroup(const QString& message, const QDomElement& root);
	

	//载入通用数据库
	void LoadFromCommonDb();
	void CreateCommonDbTable();
	void SaveProxy();
	void SaveUser(const QString& cc, const QString& phone);
	void SaveServerInfo(const QString& host, const int port);

	//从数据库载入
	void LoadFromDb();
	//创建默认表
	void CreateDefaultTable();
	//载入联系人
	void LoadContacts();


	void GetHdFromServer(const QString& jid);
	void SaveContact(const QString& jid, const QByteArray& data);
	void DeleteContact(const QString& jid);

	//操作左侧列表
	void InsertContactItem(const QString& jid, const QByteArray& data);
	void RemoveContactItem(const QString& jid);


	void PopAndSetServer();

private:
    Ui::Dialog *ui;
	QWebSocket client_websocket_;
	int task_id_ = 0;
	QSqlDatabase db_;
	QSqlDatabase common_db_;
	ProxyInfo proxy_;
	QString websocket_host_;
	int websocket_port_ = 0;
};

#endif // DIALOG_H

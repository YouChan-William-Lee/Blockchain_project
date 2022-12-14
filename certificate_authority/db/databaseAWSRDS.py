import mysql.connector
import sys
import boto3
import os

class DatabaseAWSRDS():
    def __init__(self):
        ENDPOINT="s3766194-s21.cvtg0e3lvahj.ap-southeast-2.rds.amazonaws.com"
        PORT="3306"
        USER="admin"
        PASSWD="adminadmin"
        REGION="ap-southeast-2b"
        DBNAME="p000182csitcp"
        os.environ['LIBMYSQL_ENABLE_CLEARTEXT_PLUGIN'] = '1'

        #gets the credentials from .aws/credentials
        # session = boto3.Session(profile_name='default')
        # client = session.client('rds')

        # token = client.generate_db_auth_token(DBHostname=ENDPOINT, Port=PORT, DBUsername=USER, Region=REGION)
        self.connection = mysql.connector.connect(host=ENDPOINT, user=USER, passwd=PASSWD, port=PORT, database=DBNAME, ssl_ca='SSLCERTIFICATE', autocommit=True)
        self.cursor = self.connection.cursor()

    def insertNewStudent(self, username, password, walletPassword):
        query1 = """SELECT count(*) FROM student"""
        self.cursor.execute(query1)
        studentId = self.cursor.fetchone()[0] + 1

        query2 = """INSERT INTO student (id, username, password, walletPassword, publicKey, privateKey) VALUES (%s, %s, %s, %s, %s, %s)"""
        self.cursor.execute(query2, (studentId, username, password, walletPassword, None, None,))

    def updateNewStudentKeyPairs(self, privKey, pubKey, username):
        query = """UPDATE student set privateKey = %s, publicKey = %s WHERE username = %s"""
        self.cursor.execute(query, (privKey, pubKey, username))

    def deleteExistentStudent(self, username):
        query = """DELETE FROM student WHERE username=%s"""
        self.cursor.execute(query, (username,))

    def checkUniqueStudentName(self, username):
        query = """SELECT count(*) FROM student WHERE username=%s"""
        self.cursor.execute(query, (username,))
        result = self.cursor.fetchall()
        if result[0][0] == 0:
            return True
        return False

    def checkStudentInfo(self, username, password):
        query = """SELECT * FROM student WHERE username=%s AND password=%s"""
        self.cursor.execute(query, (username, password))
        result = self.cursor.fetchall()
        if (result != []):
            return True
        return False
    
    def getStudentWalletPassword(self, username):
        query = """SELECT walletPassword FROM student WHERE username=%s"""
        self.cursor.execute(query, (username,))
        walletPW = self.cursor.fetchall()
        return walletPW[0][0]
    
    def getStudentPrivateKey(self, username):
        query = """SELECT privateKey FROM student WHERE username=%s"""
        self.cursor.execute(query, (username,))
        privKey = self.cursor.fetchall()
        return privKey[0][0]

    def getStudentPublicKey(self, username):
        query = """SELECT publicKey FROM student WHERE username=%s"""
        self.cursor.execute(query, (username,))
        pubKey = self.cursor.fetchall()
        return pubKey[0][0]
    
    def getAllStudents(self):
        query = """SELECT username FROM student"""
        self.cursor.execute(query)
        result = self.cursor.fetchall()
        studentList = []
        for student in result:
            studentList.append(student[0])
        return studentList

    def insertMessage(self, sender, receiver, time, messageType, message, encrypted_message, signed_message, signed_encrypted_message):
        query = """INSERT INTO message (sender, receiver, time, type, message, encrypted_message, signed_message, signed_encrypted_message) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"""
        self.cursor.execute(query, (sender, receiver, time, messageType, message, encrypted_message, signed_message, signed_encrypted_message))

    def insertFile(self, sender, receiver, time, fileType, file, encrypted_file, signed_file, signed_encrypted_file, fileName):
        query = """INSERT INTO files (sender, receiver, time, type, files, encrypted_file, signed_file, signed_encrypted_file, fileName) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"""
        self.cursor.execute(query, (sender, receiver, time, fileType, file, encrypted_file, signed_file, signed_encrypted_file, fileName))

    def getReceivedMessages(self, username):
        query = """SELECT * FROM message WHERE receiver=%s ORDER BY time"""
        self.cursor.execute(query, (username,))
        allMessages = self.cursor.fetchall()
        return allMessages

    def getReceivedFiles(self, username):
        query = """SELECT * FROM files WHERE receiver=%s ORDER BY time"""
        self.cursor.execute(query, (username,))
        allFiles = self.cursor.fetchall()
        return allFiles
    
    def getUserIndexUsingWalletPassword(self, walletPassword):
        query = """SELECT id FROM student WHERE walletPassword=%s"""
        self.cursor.execute(query, (walletPassword,))
        userIndex = self.cursor.fetchall()

        query = """SELECT count(*) FROM student"""
        self.cursor.execute(query)
        totalUserNumber = self.cursor.fetchall()
 
        return userIndex[0][0] - totalUserNumber[0][0] - 1

def output_type_handler(cursor, name, default_type, size, precision, scale):
    if default_type == cx_Oracle.DB_TYPE_CLOB:
        return cursor.var(cx_Oracle.DB_TYPE_LONG, arraysize=cursor.arraysize)
    if default_type == cx_Oracle.DB_TYPE_BLOB:
        return cursor.var(cx_Oracle.DB_TYPE_LONG_RAW, arraysize=cursor.arraysize)
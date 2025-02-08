// 引用库函数区
#include <Ed25519.h>      // 签名函数库
#include "SSD1306Wire.h"  // 屏幕驱动函数库
#include <Ticker.h>       // 计时中断函数库
#include <RNG.h>          // 随机数生成函数库
#include "AES.h"  //AES加密库
#include "GCM.h"  //AESGCM模式库

// 硬件或软件初始化区
SSD1306Wire display(0x3c, SDA, SCL);  // 初始化一个OLED显示器实例，指定I2C地址（0x3C），SDA（数据线）和SCL（时钟线）引脚。
Ticker timer;                         // 创建计时实例
GCM<AES256> gcm;// 创建AESGCM实例

// 《定义区》
// 定义代数区
#define SDA 4                    // I2C使用引脚设置
#define SCL 5                    // I2C使用引脚设置
#define NO_PERMISSION 0B00       // 无权限对应的编码
#define USER_PERMISSION 0B01     // 用户权限对应的编码
#define MANAGER_PERMISSION 0B10  // 经理权限对应的编码
#define ADMIN_PERMISSION 0B11    // 管理员权限对应的编码
#define HEADER1  0xA5
#define HEADER2  0x5A
const size_t HEADER_DATA_PACKET_SIZE = 222;
const size_t HEADE_SIZE = 2;
const size_t DATA_PACKET_SIZE  = 220;
const size_t SYS_DATA_SIZE = 128;
const size_t CONTROL_BYTE_SIZE = 4;
const size_t RANDOM_NUM_SIZE = 36;
const size_t SELECT_BLOCK_SIZE = 4;
const size_t ID_SIZE = 12;
const size_t IV_SIZE = 12;
const size_t AUTH_DATA_SIZE = 64;
const size_t TAG_SIZE = 16;
const size_t DATA_SIZE = 12;
const size_t KEY_SIZE = 32;
const size_t CONTROL_4_BYTE_SIZE = 1;
const size_t SIGNATURE_SIZE = 64;
const uint8_t Zone0[1] = { 0B11000000 };
const uint8_t Zone1[1] = { 0B00110000 };
const uint8_t Zone2[1] = { 0B00001100 };
const uint8_t Zone3[1] = { 0B00000011 };
const uint8_t Head[2] = {0xA5, 0x5A};

// 声明数组区
// --可变数组声明区--
uint8_t DataPacket[DATA_PACKET_SIZE];   // 暂存收到的加密数据包
uint8_t DecrySysDataPacket[SYS_DATA_SIZE];
uint8_t ControlByte[CONTROL_BYTE_SIZE];          // 暂存控制位
uint8_t RXRandomNum[RANDOM_NUM_SIZE];         // 暂存接收到的随机数
uint8_t TXRandomNum[RANDOM_NUM_SIZE];         // 暂存随机数
uint8_t SelectBlock[SELECT_BLOCK_SIZE];          // 暂存选择权限码地址块数据
String timeout;                  // 超时代码存储区
volatile bool cisrflag = false;  // 通讯超时中断标志位
uint8_t GetID[ID_SIZE];               // 暂存收到的ID
uint8_t IV[IV_SIZE];// 存储AES随机IV
uint8_t AuthData[AUTH_DATA_SIZE];// 存储AES随机AuthData
uint8_t Tag[TAG_SIZE];// 存储验证AES数据完整性Tag
uint8_t GetIV[IV_SIZE];// 存储获取到的IV
uint8_t GetAuthData[AUTH_DATA_SIZE];// 存储获取到的AuthData
uint8_t GetTag[TAG_SIZE];// 存储获取到的Tag

// -发送指令时用的空信息-
uint8_t Empty[DATA_SIZE] = {0};

// --不可变数组声明区--
// -钥匙码-
const uint8_t ID[ID_SIZE] = { 0x43, 0x6F, 0x72, 0x65, 0x20, 0x43, 0x6F, 0x6E, 0x73, 0x6F, 0x6C, 0x65 };  // 存储此验证器的ID
const uint8_t KeyEd25519PubKey[KEY_SIZE] = { 0xA8, 0xEA, 0x9C, 0x73, 0xD7, 0x5B, 0x07, 0x44, 0x2B, 0x01, 0x40, 0xB3, 0xDD, 0xF0, 0x0F, 0x6A,
                                       0x23, 0x04, 0xAB, 0x94, 0x27, 0x74, 0xE7, 0x4B, 0x8A, 0xCD, 0x92, 0x12, 0xA9, 0x0C, 0xC8, 0x15 };  // 钥匙签名公钥
const uint8_t AccessManagerEd25519PrivateKey[KEY_SIZE] = { 0x18, 0x39, 0xE6, 0xEC, 0xC8, 0x0F, 0x76, 0xCD, 0xEF, 0x37, 0x8E, 0x98, 0xAA, 0x9E, 0x03, 0x5D,
                                                     0x2D, 0x59, 0xC6, 0x10, 0x02, 0x97, 0x66, 0x4F, 0x86, 0xF4, 0xCC, 0x8F, 0x91, 0x75, 0xCB, 0xDF };  // 验证器签名私钥
const uint8_t AccessManagerEd25519PubKey[KEY_SIZE] = { 0x62, 0x32, 0x1B, 0xAE, 0x01, 0x00, 0x07, 0x1C, 0x9B, 0x75, 0x72, 0x82, 0xEB, 0xBD, 0xA5, 0x07,
                                                 0xD1, 0xF0, 0x8E, 0xAA, 0x79, 0x3A, 0x32, 0x29, 0x91, 0xBB, 0xD2, 0xC8, 0x8D, 0x78, 0x4E, 0x6F };  // 验证器签名公钥
const uint8_t AESKey[KEY_SIZE] = {0xEC, 0x69, 0xE9, 0x98, 0xFA, 0x5D, 0xCA, 0x8B, 0x6E, 0x36, 0x9C, 0xC7, 0x18, 0xD1, 0x37, 0xC0,
                             0xA5, 0xCE, 0x51, 0xB8, 0xCF, 0xAC, 0xC5, 0x66, 0x12, 0xBF, 0xEF, 0x8A, 0x59, 0x12, 0xF0, 0x2F};// 存储AES加密解密密钥

// -控制码-
const uint32_t Control1[CONTROL_4_BYTE_SIZE] = { 0x00000001 };             // 控制位1,钥匙发送的开始验证请求
const uint8_t Control2[CONTROL_BYTE_SIZE] = { 0x00, 0x00, 0x00, 0x02 };  // 控制位2,验证器回应验证开始,发送取权限码地址
const uint8_t Control3[CONTROL_BYTE_SIZE] = { 0x00, 0x00, 0x00, 0x03 };  // 控制位3,
const uint8_t Control4[CONTROL_BYTE_SIZE] = { 0x00, 0x00, 0x00, 0x04 };  // 控制码4,
const uint32_t ControlA[CONTROL_4_BYTE_SIZE] = { 0x0000000A };             // 控制位A,
const uint32_t ControlB[CONTROL_4_BYTE_SIZE] = { 0x0000000B };
const uint32_t ControlC[CONTROL_4_BYTE_SIZE] = { 0x0000000C };

// -初次验证随机数-
const uint8_t StartRandomNum[RANDOM_NUM_SIZE] = {0x23, 0x4A, 0x8B, 0x1E, 0x5F, 0x3C, 0x9D, 0x78, 0x64, 0x2F, 0xA5, 0xB3,
                                    0x19, 0x8C, 0x4D, 0x36, 0x7A, 0x5E, 0xB2, 0x0F, 0x38, 0x91, 0x44, 0x27,
                                    0x55, 0xC3, 0x6B, 0x1A, 0x8E, 0x7F, 0x3D, 0x29, 0x4F, 0x0C, 0x6D, 0x5B};// 用于初次数据的签名及其检验

// -权限验证相关设置-
const uint8_t PermissionBlockAddress[SELECT_BLOCK_SIZE] = { 0x00, 0x00, 0x00, 0x01 };  // 所需权限码在钥匙内的地址(多了可以编写表格查表)
const int PermissionByte = 0;// 选择权限所在的字节区
const uint8_t ZoneSelect = Zone1[0];// 选择权限所在的区域

// 枚举状态库
enum VState {
  idle,
  waitcode
};

VState cstate = idle;  // 初始状态置

// 中断程序-计时器内部中断（通讯恢复状态）
void CTISR() {
  cstate = idle;    // 状态置默认状态
  timer.detach();   // 停止硬件定时器，同时自动触发中断关闭
  cisrflag = true;  //标志位置1
}

void setup() {
  Serial.begin(115200);               // 设置串口波特率为115200
  RNG.begin("ID:0x0000");               // 随机数生成器初始化
  display.init();                     // 初始化显示器，确保显示屏已经准备好工作。
  display.setFont(ArialMT_Plain_10);  // 设置显示器的默认字体为ArialMT_Plain_10，大小为10px。
}

void loop() {
  display.drawString(0, 0, "Core Console");
  display.display();
  uint8_t HaderDataPacket[HEADER_DATA_PACKET_SIZE] = {0};

  if (cisrflag) {
    cisrflag = false;
    display.clear();                                 //  清屏
    display.drawString(0, 20, "ConnectionTimeout");  // 显示通讯超时
    display.drawString(0, 30, timeout);              // 显示超时代码
    display.display();                               // 显示
    block(2000);                                     // 阻塞两秒
    disclearblock(0, 20, 128, 20);                   //
  }
  // 接收数据函数段
  else if (Serial.available() >= HEADER_DATA_PACKET_SIZE) {
    delay(10);                                // 等待数据发完
    Serial.readBytes(HaderDataPacket, HEADER_DATA_PACKET_SIZE);  // 将缓冲区内数据包放到数组内方便处理
    while (Serial.read() >= 0) {}             // 清掉串口缓存
    if(HaderDataPacket[0] == HEADER1 && HaderDataPacket[1] == HEADER2)
    {
      memcpy(DataPacket, &HaderDataPacket[2], DATA_PACKET_SIZE);
      ProcessPacket();                    // 进入数据包处理函数
    } else {
      while (Serial.read() >= 0) {}             // 清掉串口缓存
    }
  }
}

// 处理内数据包函数
void ProcessPacket() {
  uint8_t EncrySysDataPacket[SYS_DATA_SIZE] = { 0 };
  uint8_t ToVerifyID[ID_SIZE] = { 0 };             // 创建数据分类块
  uint8_t ToVerifySignature[SIGNATURE_SIZE] = { 0 };             // 创建数据分类块
  uint8_t ToVerifyUnsignedOriginalData[SIGNATURE_SIZE] = { 0 };  // 创建数据分类块
  memset(DecrySysDataPacket, 0, sizeof(DecrySysDataPacket));
  memcpy(GetIV, DataPacket, IV_SIZE);                                                        // 给数据分类存放
  memcpy(GetAuthData, &DataPacket[12], AUTH_DATA_SIZE);                                        // 给数据分类存放
  memcpy(EncrySysDataPacket, &DataPacket[76], SYS_DATA_SIZE);
  memcpy(GetTag, &DataPacket[204], TAG_SIZE);
  decryAESGCM(AESKey, 32, EncrySysDataPacket, DecrySysDataPacket, GetIV, IV_SIZE, GetAuthData, AUTH_DATA_SIZE, GetTag, TAG_SIZE);
  memcpy(ToVerifySignature, DecrySysDataPacket, SIGNATURE_SIZE);
  memcpy(ToVerifyUnsignedOriginalData, &DecrySysDataPacket[64], SIGNATURE_SIZE);
  if (cstate == idle) {
    memcpy(&ToVerifyUnsignedOriginalData[24], StartRandomNum, RANDOM_NUM_SIZE);                                               // 给数据分类存放
    bool isValid = Ed25519::verify(ToVerifySignature, KeyEd25519PubKey, ToVerifyUnsignedOriginalData, SIGNATURE_SIZE);  // 将分类好的数据进行验证
    if (isValid) {
      memcpy(RXRandomNum, &DecrySysDataPacket[88], RANDOM_NUM_SIZE);
      memcpy(GetID, &DecrySysDataPacket[76], ID_SIZE);
      memcpy(ControlByte, &DecrySysDataPacket[124], CONTROL_BYTE_SIZE);  // 将控制位挪到控制位格式转换区
      Control();                                       // 进入读取控制位分配任务函数
    }
    else
    {
      // 验证失败显示
      display.drawString(0, 20, "Verification Failed");
      display.display();
      block(1000);
      disclearblock(0, 20, 128, 10);
      cstate = idle;
    }
  }
  else
  {
    memcpy(&ToVerifyUnsignedOriginalData[24], TXRandomNum, RANDOM_NUM_SIZE);                                             // 给数据分类存放
    memset(TXRandomNum, 0, sizeof(TXRandomNum)); // 将 TXRandomNum 的所有元素清零
    bool isValid = Ed25519::verify(ToVerifySignature, KeyEd25519PubKey, ToVerifyUnsignedOriginalData, 64);  // 将分类好的数据进行验证
    if (isValid) {
      memcpy(RXRandomNum, &DecrySysDataPacket[88], RANDOM_NUM_SIZE);
      memcpy(ToVerifyID, &DecrySysDataPacket[76], ID_SIZE);
      if(memcmp(GetID, ToVerifyID, ID_SIZE) == 0)
      {
        memcpy(ControlByte, &DecrySysDataPacket[124], CONTROL_BYTE_SIZE);  // 将控制位挪到控制位格式转换区
        Control();                                       // 进入读取控制位分配任务函数
      }
      else
      {
        display.drawString(0, 20, "ID Failed");
        display.display();
        block(1000);
        disclearblock(0, 20, 128, 10);
        cstate = idle;
      }
    }
    else
    {
      // 验证失败显示
      display.drawString(0, 20, "Verification Failed");
      display.display();
      block(1000);
      disclearblock(0, 20, 128, 10);
      cstate = idle;
    }
  }
}

void Control() {
  String AL;
  uint32_t Control4Byte[1];                                                                                    // 暂存转换后的控制位
  Control4Byte[0] = (ControlByte[0] << 24) | (ControlByte[1] << 16) | (ControlByte[2] << 8) | ControlByte[3];  // 转换控制位格式为uint32_t
  if(Control4Byte[0] == Control1[0] && cstate == idle)
  {
    CheckCode();
  }
  else if (((Control4Byte[0] == ControlA[0]) || (Control4Byte[0] == ControlB[0]) || (Control4Byte[0] == ControlC[0])) && cstate == waitcode) {
    cstate = idle;
    int code1 = VerifyCode();
    if(code1 == 1){
      AL = "User";
    } else if(code1 == 2){
      AL = "Manager";
    } else if(code1 == 3){
      AL = "Admin";
    }
    display.drawString(0, 10, "Access Level:"+AL);
    display.drawString(0, 20, "Verification Passed");
    display.display();                                  // 显示
    RNG.rand(Empty, sizeof(Empty));
    memset(Empty, code1, 1);                       
    SendData(Empty, DATA_SIZE, Control3);
    //执行相应的代码
    block(2000);
    disclearblock(0, 10, 128, 20);
  }
  else
  {
    cstate = idle;
    display.drawString(0, 20, "Error Com");
    display.display();
    block(1000);
  }
}

void CheckCode() {
  cstate = waitcode;                              // 改变当前状态
  timeout = "check";                              // 改变当前状态（用于报错显示）
  SendData(PermissionBlockAddress, SELECT_BLOCK_SIZE, Control2);
  timer.attach(2, CTISR);                         // 硬件定时器设置，自动触发中断回到默认状态
}

int VerifyCode() {
  cstate = idle;
  timer.detach();  // 停止硬件定时器
  uint8_t PermissionBlock[DATA_SIZE] = { 0 };
  memcpy(PermissionBlock, &DecrySysDataPacket[64], DATA_SIZE);

  // 提取当前区的权限值
  uint8_t permission = (PermissionBlock[PermissionByte] & ZoneSelect) >> __builtin_ctz(ZoneSelect);

  if (permission == ADMIN_PERMISSION) {
    return 3;
  } else if (permission == MANAGER_PERMISSION) {
    return 2;
  } else if (permission == USER_PERMISSION) {
    return 1;
  } else {
    return 0;
  }
}

// 加密数据
void encryAESGCM(const uint8_t *key, size_t keylen,uint8_t *inputtext, size_t textlen, uint8_t *output,uint8_t *tag, size_t taglen)
{
  gcm.clear();
  memset(IV, 0, sizeof(IV));
  memset(AuthData, 0, sizeof(AuthData));
  memset(Tag, 0, sizeof(Tag));

  RNG.rand(IV, sizeof(IV));
  RNG.rand(AuthData, sizeof(AuthData));

  gcm.setKey(key, keylen);
  gcm.setIV(IV, sizeof(IV));
  gcm.addAuthData(AuthData, sizeof(AuthData));

  gcm.encrypt(output, inputtext, textlen);
  gcm.computeTag(tag, taglen);
}

// 只能解密128字节的加密数据，如果需要变动就将内部的128改成其他的数字
const size_t DECRY_AES_SIZE = 128;// 在这改宽度
void decryAESGCM(const uint8_t *key, size_t keylen, uint8_t *inputtext, uint8_t *output, 
                 uint8_t *inputiv, size_t ivlen, uint8_t *inputauthdata, size_t authdatalen, 
                 uint8_t *inputtag, size_t taglen)
{
  gcm.clear();
  uint8_t tempBuffer[DECRY_AES_SIZE] = {0};

  gcm.setKey(key, keylen);
  gcm.setIV(inputiv, ivlen);
  gcm.addAuthData(inputauthdata, authdatalen);

  gcm.decrypt(tempBuffer, inputtext, DECRY_AES_SIZE);

  if (!gcm.checkTag(inputtag, taglen))
  {
    volatile uint8_t *p = tempBuffer;
    for (size_t i = 0; i < DECRY_AES_SIZE; i++) {
        p[i] = 0;  // 清零数据，防止泄露信息
    }
    decryerror();
    return;
  }
  memcpy(output, tempBuffer, DECRY_AES_SIZE);
}

// 要塞入的数据不能大于12个长度，且只能发送uint8
void SendData(const uint8_t *input, size_t length,const uint8_t *com)
{
  uint8_t ToBeSignature[SIGNATURE_SIZE] = {0};
  uint8_t Signature[SIGNATURE_SIZE] = {0};
  uint8_t ToBeEncrySysDataPacket[SYS_DATA_SIZE] = { 0 };        // 暂存需要加密的内数据包
  uint8_t EncrySysDataPacket[SYS_DATA_SIZE] = { 0 };        // 暂存加密好的内数据包
  uint8_t NoHeadDataPacket[DATA_PACKET_SIZE] = { 0 };        // 暂存需要发送的外数据包
  uint8_t HaderDataPacket[HEADER_DATA_PACKET_SIZE] = {0};// 加包头后的数据包
  memcpy(ToBeSignature, input, length);
  RNG.rand(TXRandomNum, sizeof(TXRandomNum));         // 生成挑战随机数
  memcpy(&ToBeSignature[12], ID, ID_SIZE);      // 将ID数据送入
  memcpy(&ToBeSignature[24], RXRandomNum, RANDOM_NUM_SIZE);    // 将挑数据送入
  memset(RXRandomNum, 0, sizeof(RXRandomNum));
  memcpy(&ToBeSignature[60], com, CONTROL_BYTE_SIZE);  // 将挑数据送入
  Ed25519::sign(Signature, AccessManagerEd25519PrivateKey, AccessManagerEd25519PubKey, ToBeSignature, 64);
  memcpy(&ToBeSignature[24], TXRandomNum, RANDOM_NUM_SIZE);
  memcpy(ToBeEncrySysDataPacket, Signature, SIGNATURE_SIZE);
  memcpy(&ToBeEncrySysDataPacket[64], ToBeSignature, SIGNATURE_SIZE);
  encryAESGCM(AESKey, KEY_SIZE, ToBeEncrySysDataPacket, SYS_DATA_SIZE, EncrySysDataPacket, Tag, 16);
  memcpy(NoHeadDataPacket, IV, IV_SIZE);
  memcpy(&NoHeadDataPacket[12], AuthData, AUTH_DATA_SIZE);
  memcpy(&NoHeadDataPacket[76], EncrySysDataPacket, SYS_DATA_SIZE);
  memcpy(&NoHeadDataPacket[204], Tag, TAG_SIZE);
  memcpy(HaderDataPacket, Head, HEADE_SIZE);
  memcpy(&HaderDataPacket[2], NoHeadDataPacket, DATA_PACKET_SIZE);
  Serial.write(HaderDataPacket, HEADER_DATA_PACKET_SIZE);          // 发送数据包
}

// 防止引发后台看门狗触发重启的阻塞函数
void block(int input) {
  unsigned long startTime = millis();     // 记录开始时间
  unsigned long lastYield = millis();     // 上次调用yield的时间
  while (millis() - startTime < input) {  // 判断已经过去了多少毫秒
    if (millis() - lastYield >= 10) {     // 每10毫秒调用一次yield
      yield();                            // 执行底层代码，避免看门狗叫
      lastYield = millis();               // 转移数据为执行判断
    }
  }
}

void decryerror()
{
  display.drawString(0, 10, "AES Error");  // 显示
  display.display();                                  // 显示
  block(1000);
  display.clear();                                 //  清屏
}

// 清屏特定区域函数
void disclearblock(int x, int y, int width, int height) {
  display.setColor(BLACK);                // 设置颜色
  display.fillRect(x, y, width, height);  // 从什么地方开始填充多宽多高的区域
  display.display();                      // 显示
  display.setColor(WHITE);                // 设置颜色
}
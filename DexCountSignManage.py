import hashlib
import shutil

def reader2Hex(reader):
    intreader = int.from_bytes(reader, 'big')
    return hex(intreader)

'''
  
     计算sum
     返回byte
     author Ricardo.Lv
     date 2022/4/24-9:48
 '''
def countSum(dex):
    dex.seek(12, 0)
    VarA = 1
    VarB = 0
    flag = 0
    CheckSum = 0
    while True:
        srcBytes = []
        for i in range(1024):  # 一次只读1024个字节，防止内存占用过大
            ch = dex.read(1)
            if not ch:  # 如果读取到末尾，设置标识符，然后退出读取循环
                flag = 1
                break
            else:
                ch = int.from_bytes(ch, 'big')  # 将字节转为int类型，然后添加到数组中
                srcBytes.append(ch)
        icount = 0
        while icount < len(srcBytes):

            VarA = (VarA + srcBytes[icount]) % 65521
            VarB = (VarB + VarA) % 65521
            icount += 1
        if flag == 1:
            CheckSum = (VarB << 16) + VarA
            break
    checksum_byte = CheckSum.to_bytes(4,byteorder='little',signed=False)
    return checksum_byte

'''
 
    计算sign
    返回byte
    author Ricardo.Lv
    date 2022/4/24-9:49
'''
def countSign(dex):
    dex.seek(32, 0)
    countsign = hashlib.sha1(dex.read()).digest()
    return countsign

def countSize(dex):
    dex.seek(0, 0)
    file_byte = dex.read()
    size = len(file_byte).to_bytes(4,byteorder='little',signed=False)
    return size
class DexCountSignManage():


    '''

        验证sign
        author Ricardo.Lv
        date 2022/4/24-9:42
    '''
    def checkSign(dex):
        dex.seek(12, 0)
        files_sha = dex.read(20)
        files_sha = reader2Hex(files_sha)
        count_sha_byte = countSign(dex)
        count_sha = hex(int.from_bytes(count_sha_byte, 'big'))
        print("files_sha:", files_sha)
        print("count_sha:", count_sha)
        return files_sha.strip() == count_sha.strip()
    '''
     
        重新计算dex大小
        author Ricardo.Lv
        date 2022/4/27-16:14
    '''
    def checkSize(dex):
        countsize_byte = hex(int.from_bytes(countSize(dex), 'big'))
        dex.seek(32,0)
        filesize_byte = reader2Hex(dex.read(4))
        print("count_size:",countsize_byte)
        print("files_size:",(filesize_byte))
        return filesize_byte.strip()==countsize_byte.strip()
    '''
     
        检查sum
        author Ricardo.Lv
        date 2022/4/24-9:42
    '''
    def checkSum(dex):
        dex.seek(8, 0)
        file_checksum = reader2Hex(dex.read(4))
        countsum_byte = countSum(dex)
        checksum_str = hex(int.from_bytes(countsum_byte, 'big'))
        print("files_checksum:", file_checksum)
        print("count_checksum:",checksum_str)
        return checksum_str.strip() == file_checksum.strip()

    '''
     
        重新计算sum和sign并写回
        author Ricardo.Lv
        date 2022/4/24-9:43
    '''
    def againCount_SignSum(path):
        shutil.copy(path,"output.dex")
        output_dex = open("output.dex","rb+")
        #重新计算size
        print(DexCountSignManage.checkSize(output_dex))
        countsize_byte = countSize(output_dex)
        output_dex.seek(32,0)
        output_dex.write(countsize_byte)
        #重新计算签名
        print(DexCountSignManage.checkSign(output_dex))
        countsign_byte = countSign(output_dex)
        output_dex.seek(12,0)
        output_dex.write(countsign_byte)
        #重新计算sum
        print(DexCountSignManage.checkSum(output_dex))
        countsum_byte = countSum(output_dex)
        output_dex.seek(8,0)
        output_dex.write(countsum_byte)
        print("sign和sum重新计算完毕，开始校验...")
        if DexCountSignManage.checkSize(output_dex) and DexCountSignManage.checkSum(output_dex) and DexCountSignManage.checkSign(output_dex) :
            print("校验结束，结果：校验成功！")
            return True
        else:
            print("校验结束，结果：校验失败。")
            return False
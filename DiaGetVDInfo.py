#!/usr/bin/env python
# coding: utf-8


# In[1]:

import comtypes
import comtypes.client
import os

msdia = comtypes.client.GetModule(r'C:\Program Files (x86)\Common Files\Microsoft Shared\VC\amd64\msdia80.dll')

from comtypes.gen.Dia2Lib import *

try:
    dia = comtypes.client.CreateObject(msdia.DiaSource)
except Exception as exc:
    print('Exception creating DIA object:\n  %s\nTry to regsrv32.exe ...msdia80.dll' % (str(exc)))
    exit(1)

DGVDI_Version = 'DiaGetVDInfo v2'
print(DGVDI_Version)
print(os.getcwd())
with open('Result.txt', 'w', encoding="utf-8") as f:
    print(DGVDI_Version, file=f)


# In[2]:

import pefile
import requests
import shutil

SYMBOLS_SERVER = 'https://msdl.microsoft.com/download/symbols'

isfail = 0

class PEFile(pefile.PE):
    def __init__(self, path):
        pefile.PE.__init__(self, path)

        self.path = path
        self.pdbFileName = None
        self.pdbObj = None
        self.symbols = None

        print('%s' % self.path)
        with open('Result.txt', 'a', encoding="utf-8") as f:
            print(self.path, file=f)

    def downloadPDB(self, localCache=r'E:\Symbols'):
        def getPDBURL(pe):
            #pe.parse_data_directories()
            string_version_info = {}
            for fileinfo in pe.FileInfo[0]:
                if fileinfo.Key.decode() == 'StringFileInfo':
                    for st in fileinfo.StringTable:
                        for entry in st.entries.items():
                            string_version_info[entry[0].decode()] = entry[1].decode()
            verStr = string_version_info['ProductVersion']
            for directory in pe.DIRECTORY_ENTRY_DEBUG:
                debug_entry = directory.entry
                if hasattr(debug_entry, 'PdbFileName'):
                    pdb_file = debug_entry.PdbFileName[:-1].decode('ascii')
                    guid = debug_entry.Signature_String
                    guid = guid.upper()
                    url = f'/{pdb_file}/{guid}/{pdb_file}'
                    pdbFileName = f'{pdb_file[:-4]}-{verStr}.pdb'
                    return url, pdbFileName
            return None

        path = self.path
        pdbUrl, pdbFileName = getPDBURL(self)

        print(SYMBOLS_SERVER + pdbUrl)
        with open('Result.txt', 'a', encoding="utf-8") as f:
            print(SYMBOLS_SERVER + pdbUrl, file=f)
        print(pdbFileName)
        with open('Result.txt', 'a', encoding="utf-8") as f:
            print(pdbFileName, file=f)
            print('', file=f)

        if not os.path.exists(pdbFileName):
            pdbPath = pdbFileName
            if os.path.exists(localCache):
                pdbPath = localCache + pdbUrl
                pdbPath = os.path.realpath(pdbPath)
            if not os.path.exists(pdbPath):
                print('Downloading...')
                with open(pdbPath, 'wb') as f:
                    f.write(requests.get(SYMBOLS_SERVER + pdbUrl).content)
            if pdbPath != pdbFileName:
                shutil.copyfile(pdbPath, pdbFileName)
        self.pdbFileName = pdbFileName

    def loadPDB(self):
        self.downloadPDB()
        try:
            dia = comtypes.client.CreateObject(msdia.DiaSource)
            dia.loadDataFromPdb(self.pdbFileName)
            diaSession = dia.openSession()
            self.pdbObj = diaSession
        except Exception as exc:
            print(('[!] loadDataFromPdb() error %s' % (str(exc))))
            os.remove(self.pdbFileName)
            global isfail
            isfail = isfail + 1


with open('Result.txt', 'a', encoding="utf-8") as f:
    print('', file=f)
twinuipcshell = PEFile(r"C:\Windows\System32\twinui.pcshell.dll")
twinuipcshell.loadPDB()
actxprxy = PEFile(r"C:\Windows\System32\actxprxy.dll")
actxprxy.loadPDB()
if isfail > 0:
    exit


# In[3]:

udtEnumToStr = ('struct', 'class', 'union', 'interface')
# Utility class for capturing some of the data from UDT symbol list in PDB file
class PDBSymbol:

    @classmethod
    def fromDia(cls, symbol_data):
        return PDBSymbol(udtEnumToStr[symbol_data.udtKind], symbol_data.name, symbol_data.undecoratedName, symbol_data.virtualAddress, symbol_data.length)

    def __init__(self, kind = '', name = '', undName = '', rva = 0, size = 0):

        self.kind = kind
        self.name = name
        self.undName = undName
        self.rva = rva
        self.size = size
        self.pe = None

    def __str__(self):

        sstr = '0x%08x (%4dB) %s\t%s' % (self.rva, self.size, self.kind, self.name)

        return sstr

    def __repr__(self):
        return f'<PDBSymbol {str(self)}>'

    # required for hash
    def __hash__(self):
        return hash((self.name, self.rva, self.kind))

    # required for hash, when buckets contain multiple items
    def __eq__(self, other):
        return (self.name == other.name and self.rva == other.rva and self.kind == other.kind)

    def __contains__(self, key):
        return self.__eq__(key)

    def readData(self, length=None):
        if length is None:
            length = self.size

        return self.pe.get_data(self.rva, length)

# EOF


# In[4]:

# parse the input PDB
def parsePDB(pe):
    pdbObj = pe.pdbObj
    syms = set()

    # iterate the public syms to find all vtables
    for symb in pdbObj.globalScope.findChildren(SymTagPublicSymbol, None, 0):
        symbol_data = symb.QueryInterface(IDiaSymbol)
        symbol_obj = PDBSymbol.fromDia(symbol_data)

        syms.add(symbol_obj)

        #print(symbol_data.undecoratedName, symbol_data.name)

    # iterate all UDT/private? symbols
    for symb in pdbObj.globalScope.findChildren(SymTagUDT, None, 0):
        symbol_data = symb.QueryInterface(IDiaSymbol)
        #print(symbol_data.undecoratedName, symbol_data.name)
        symbol_obj = PDBSymbol.fromDia(symbol_data)

        syms.add(symbol_obj)


    syms = list(syms)
    for sym in syms:
        sym.pe = pe
    return syms

print('parsePDB: ' + twinuipcshell.pdbFileName)
twinuipcshell.symbols = parsePDB(twinuipcshell)
print('parsePDB: ' + actxprxy.pdbFileName)
actxprxy.symbols = parsePDB(actxprxy)


# In[5]:

symMap = {c.name: c for c in twinuipcshell.symbols + actxprxy.symbols}


# In[6]:

# dump guid
def GUIDToStr(guidbytes):
    return '%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X' % (
        int.from_bytes(guidbytes[:4], 'little'),
        int.from_bytes(guidbytes[4:6], 'little'),
        int.from_bytes(guidbytes[6:8], 'little'),
        *[int.from_bytes(guidbytes[i:i+1], 'little') for i in range(8, 16)]
    )

def printGuidSym(symName):
    print('%s...' % (symName))
    try:
        with open('Result.txt', 'a', encoding="utf-8") as f:
            print('%s: %s' % (symName, GUIDToStr(symMap[symName].readData())), file=f)
    except Exception as exc:
        with open('Result.txt', 'a', encoding="utf-8") as f:
            print('%s: %s' % (symName, str(exc)), file=f)

printGuidSym("CLSID_ImmersiveShell")
printGuidSym("SID_VirtualDesktopManager")
printGuidSym("IID_IVirtualDesktopManagerInternal")
printGuidSym("IID_IVirtualDesktopNotification")
printGuidSym("SID_VirtualDesktopNotificationService")
printGuidSym("IID_IVirtualDesktopNotificationService")
printGuidSym("IID_IVirtualDesktop")
printGuidSym("SID_VirtualDesktopPinnedApps")
printGuidSym("IID_IVirtualDesktopPinnedApps")
printGuidSym("IID_IVirtualDesktopManagerInternal2")
printGuidSym("IID_IVirtualDesktopAccessibility")
printGuidSym("IID_IVirtualDesktopManager")
printGuidSym("SID_VirtualDesktopAnimationSyncNotificationService")
printGuidSym("SID_VirtualDesktopController")
printGuidSym("SID_VirtualDesktopDataSource")
printGuidSym("SID_VirtualDesktopGestureHandler")
printGuidSym("SID_VirtualDesktopHotkeyHandler")
printGuidSym("SID_VirtualDesktopSwitcher")
printGuidSym("SID_VirtualDesktopTabletModePolicyService")
printGuidSym("IID_IVirtualDesktop2")
printGuidSym("IID_IVirtualDesktopAccessibility")
printGuidSym("IID_IVirtualDesktopAnimationSyncNotification")
printGuidSym("IID_IVirtualDesktopAnimationSyncNotificationService")
printGuidSym("IID_IVirtualDesktopHotkeyHandler")
printGuidSym("IID_IVirtualDesktopSwitcherHost")
printGuidSym("IID_IVirtualDesktopSwitcherInvoker")
printGuidSym("IID_IVirtualDesktopTabletModePolicyService")


# In[7]:

symMap = {c.name: c for c in twinuipcshell.symbols + actxprxy.symbols}

# dump vfte
def dumpVFT(vftName):
    try:
        vftSym = symMap[vftName]
        with open('Result.txt', 'a', encoding="utf-8") as f:
            print("Dumping vftable: %s" % vftSym.undName, file=f)
        vftData = vftSym.readData()
        vftPtrs = [int.from_bytes(vftData[c:c+8], 'little') - vftSym.pe.OPTIONAL_HEADER.ImageBase for c in range(0, len(vftData), 8)]
        symMap2 = {c.rva: c for c in vftSym.pe.symbols}
        for i, ptr in enumerate(vftPtrs):
            if ptr in symMap2:
                with open('Result.txt', 'a', encoding="utf-8") as f:
                    print("    Method %2d: %s (%s)" % (i, symMap2[ptr].undName, symMap2[ptr].name), file=f)
            else:
                with open('Result.txt', 'a', encoding="utf-8") as f:
                   print("    Method %2d: Unknown (0x%X)" % (i, ptr), file=f)
    except Exception as exc:
        with open('Result.txt', 'a', encoding="utf-8") as f:
            print("%s: %s" % (vftName, str(exc)), file=f)

with open('Result.txt', 'a', encoding="utf-8") as f:
    print ('', file=f)
dumpVFT('??_7CVirtualDesktopManager@@6BIVirtualDesktopManagerInternal@@@')
dumpVFT('??_7CVirtualDesktopManager@@6BIVirtualDesktopManagerInternal2@@@')
with open('Result.txt', 'a', encoding="utf-8") as f:
    print ('', file=f)
dumpVFT('??_7VirtualDesktopsApi@@6B@')
with open('Result.txt', 'a', encoding="utf-8") as f:
    print ('', file=f)
dumpVFT('??_7CVirtualDesktop@@6B?$ChainInterfaces@UIVirtualDesktop2@@UIVirtualDesktop@@VNil@Details@WRL@Microsoft@@V3456@V3456@V3456@V3456@V3456@V3456@V3456@@WRL@Microsoft@@@')
with open('Result.txt', 'a', encoding="utf-8") as f:
    print ('', file=f)
dumpVFT('??_7?$VirtualDesktopNotificationBase@UIVirtualDesktopNotification@@@@6B@')
with open('Result.txt', 'a', encoding="utf-8") as f:
    print ('', file=f)

while True:
    choice = input("> Full debug or (e)xit?")
    if choice == 'e' :
        exit(1)
    else:
        break


# In[8]:

print (actxprxy.pdbFileName + '...')
with open('Result_full.txt', 'w', encoding="utf-8") as f:
    print ('ActXPrxy', file=f)
with open('Result_full.txt', 'a', encoding="utf-8") as f:
    print ('--------------------------------------------------------------------------------', file=f)

symMap = {c.name: c for c in actxprxy.symbols}

def printGuidSym2(symName):
    try:
        with open('Result_full.txt', 'a', encoding="utf-8") as f:
            print('%s: %s' % (symName, GUIDToStr(symMap[symName].readData())), file=f)
    except Exception as exc:
        with open('Result_full.txt', 'a', encoding="utf-8") as f:
            print('%s: %s' % (symName, str(exc)), file=f)

for c in actxprxy.symbols:
  try:
       printGuidSym2(c.name)
  except Exception as exc:
       with open('Result_full.txt', 'a', encoding="utf-8") as f:
           print('%s: %s' % (c.name, str(exc)), file=f)

with open('Result_full.txt', 'a', encoding="utf-8") as f:
    print ('--------------------------------------------------------------------------------', file=f)

with open('Result_full.txt', 'a', encoding="utf-8") as f:
    print ('', file=f)

print (twinuipcshell.pdbFileName + '...')
with open('Result_full.txt', 'a', encoding="utf-8") as f:
    print ('twinui.pcshell', file=f)
with open('Result_full.txt', 'a', encoding="utf-8") as f:
    print ('--------------------------------------------------------------------------------', file=f)

symMap = {c.name: c for c in twinuipcshell.symbols}

for c in twinuipcshell.symbols:
  try:
       printGuidSym2(c.name)
  except Exception as exc:
       with open('Result_full.txt', 'a', encoding="utf-8") as f:
            print("%s: %s" % (c.name, str(exc)), file=f)

with open('Result_full.txt', 'a', encoding="utf-8") as f:
    print ('--------------------------------------------------------------------------------', file=f)

symMap = {c.name: c for c in twinuipcshell.symbols + actxprxy.symbols}

def dumpVFT2(vftName):
    vftSym = symMap[vftName]

    #if "const CVirtualDesktopManager" in vftSym.undName:

    try:
       Pos = vftSym.undName.index("const ")
    except:
       Pos = -1
    if Pos == 0:

         with open('Result_full.txt', 'a', encoding="utf-8") as f:
             print(vftName, file=f)
         with open('Result_full.txt', 'a', encoding="utf-8") as f:
             print("Dumping vftable: %s" % vftSym.undName, file=f)
         vftData = vftSym.readData()
         vftPtrs = [int.from_bytes(vftData[c:c+8], 'little') - vftSym.pe.OPTIONAL_HEADER.ImageBase for c in range(0, len(vftData), 8)]
         symMap2 = {c.rva: c for c in vftSym.pe.symbols}
         for i, ptr in enumerate(vftPtrs):
             if ptr in symMap2:
                 with open('Result_full.txt', 'a', encoding="utf-8") as f:
                     print("    Method %2d: %s (%s)" % (i, symMap2[ptr].undName, symMap2[ptr].name), file=f)
             else:
                 with open('Result_full.txt', 'a', encoding="utf-8") as f:
                     print("    Method %2d: Unknown (0x%X)" % (i, ptr), file=f)
             if i == 0:
               print(i)
             else:
               print(i, end =" ")
    else:
      pass

with open('Result_full.txt', 'a', encoding="utf-8") as f:
    print ('', file=f)

for c in actxprxy.symbols + twinuipcshell.symbols:
  try:
       dumpVFT2(c.name)
  except Exception as exc:
       with open('Result_full.txt', 'a', encoding="utf-8") as f:
           print("%s: %s" % (c.name, str(exc)), file=f)

#
#!/usr/bin/env python

__description__ = 'Extract image and hash it plugin for oledump.py'
__author__ = 'Jon Armer'
__version__ = '0.0.2'
__date__ = '2019/12/03'

"""

Source code put in public domain by Jon Armer, no Copyright
Use at your own risk

This plugin will attempt to extract image and hash it

Usage:
$ python oledump.py ../test_docs/image_in_doc.doc -p plugin_extract_img.py --pluginoptions save=../test_docs/extract_image.jpeg
  1:       114 '\x01CompObj'
  2:      4096 '\x05DocumentSummaryInformation'
  3:      4096 '\x05SummaryInformation'
  4:      6984 '1Table'
  5:    459865 'Data'
               Plugin: Extract and sha256 hash image plugin. save image with --pluginoptions save=<location> 
                 use option -q to dump the following data
                 sha256 hash is: 5737761889ed2d709d00a65d84cfe4dee120c8c2d98054e5fff073652021aaaf
  6:      4096 'WordDocument'

$ sha256sum ../test_docs/extract_image.jpeg 
5737761889ed2d709d00a65d84cfe4dee120c8c2d98054e5fff073652021aaaf  ../test_docs/extract_image.jpeg

$ file ../test_docs/extract_image.jpeg 
../test_docs/extract_image.jpeg: JPEG image data, JFIF standard 1.02, resolution (DPI), density 300x300, segment length 16, Exif Standard: [TIFF image data, big-endian, direntries=7, orientation=upper-left, xresolution=98, yresolution=106, resolutionunit=2, software=Adobe Photoshop CS3 Windows, datetime=2008:07:01 09:49:29], baseline, precision 8, 2170x1560, components 3


History:
  2019/12/01: start

Todo:
    - Add in other shape records
    - Return shape name
"""

import struct
from Crypto.Hash import SHA256


class extract_and_hash_image(cPluginParent):
    macroOnly = False

    name = 'Extract and sha256 hash image plugin. save image with --pluginoptions save=<folder_location>'

    #  options is a string passed to --pluginoptions.
    def __init__(self, name, stream, options):
        # Storing the arguments for later use by Analyze method
        self.streamname = name
        self.stream = stream
        self.options = options
        self.save = ""
        self.index = 0
	self.img_info = [] # TODO make dict when we can parse shape name and other info. 

        self.ran = False

    # Method Analyze is called by oledump to let the plugin analyze the stream.
    # This method must return a list of strings: this is the plugin output to be displayed by oledump.
    # This method must also set object property ran to True to have oledump display output for this plugin.
    def Analyze(self):
        result = []
        curindex = 0

        for option in self.options.split(','):
            if option.startswith("save"):
                # check if folder is created
                self.save = option.split("=")[1]


        if self.stream and self.streamname == ['Data']:
            while(self.index < len(self.stream)):
                curindex = self.index
                data_element_size = self.read_dword()
                self.parse_PICAndOfficeArtData(curindex + data_element_size) # could probably make generic classes so we can read and write the records

                self.index = curindex + data_element_size # skip element

            if self.img_info:
                self.ran = True
                # for key, val in self.img_info: # when dict
                for val in self.img_info:
                    result.append("image sha256 hash is: {}".format(val))

        return result

    
    def read_byte(self): 
        val = ord(self.stream[self.index])
        self.index += 1
        return val

    def read_bytes(self, num):
        val = self.stream[self.index:self.index + num]
        self.index += num
        return val

    def read_sword(self): # could use read bytes, and then do unpacking
        val = struct.unpack("<h", self.stream[self.index:self.index + 2])[0]
        self.index += 2
        return val

    def read_sdword(self):
        val = struct.unpack("<i", self.stream[self.index:self.index + 4])[0]
        self.index += 4
        return val

    def read_word(self):
        val = struct.unpack("<H", self.stream[self.index:self.index + 2])[0]
        self.index += 2
        return val

    def read_dword(self):
        val = struct.unpack("<I", self.stream[self.index:self.index + 4])[0]
        self.index += 4
        return val
    
    
    def parse_OfficeArtRecordHeader(self):
        '''
        A OfficeArtRecordHeader is 8 bytes and is made up of 
            1 nibble recVer, least significate nibble once ushort has been read
            3 nibble recInstance
            1 ushort recType
            1 uint recLen
        '''
    
        rec_ver_instance = self.read_word()
        recType = self.read_word()
        recLen = self.read_dword()
    
        return rec_ver_instance & 0xF, (rec_ver_instance & 0xFFF0) >> 4, recType, recLen
    
    
    
    def parse_mfpf(self):
        '''
        The mfpf struct is 8 bytes and is made up of
            1 ushort mm
            1 ushort xExt
            1 ushort yExt
            1 ushort swHMF
        '''
    
        mm = self.read_word()
        xExt = self.read_word()
        yExt = self.read_word()
        swHMF = self.read_word()
        
        return mm, xExt, yExt, swHMF
        
    
    def parse_innerHeader(self):
        '''
        The innerHeader struct is 14 bytes and is made up of 
            1 uint grf
            1 uint padding1
            1 ushort mmPM
            1 uint padding2
        '''
    
        grf = self.read_dword()
        self.index += 4
        mmPM = self.read_word()
        # padding2 = struct.unpack("<I".read(4))
        self.index += 4
    
        return grf, mmPM
        
    def parse_picmid(self):
        '''
        The picmid struct is 38 bytes and is made up of
            1 short dxaGoal, initial width of pic in twips. # Why is this signed?
            1 short dyaGoal
            1 ushort mx
            1 ushort my
            1 ushort dxaReserved1
            1 ushort dyaReserved1
            1 ushort dxaReserved2
            1 ushort dyaReserved2
            1 byte fReserved
            1 byte bpp
            4 byte Brc80 struct, border above picture
            4 byte Brc80 struct, border left picture
            4 byte Brc80 struct, border below picture
            4 byte Brc80 struct, border right picture
            1 ushort dxaReserved3
            1 ushort dyaReserved3
        '''
    
        dxaGoal = self.read_sword()
        dyaGoal = self.read_sword()
        mx = self.read_word()
        my = self.read_word()
        self.index += 8
        self.index += 1
        bpp = self.read_byte()
        # can parse Brc80, but haven't added in 
        self.index += 16
        # above_Brc80 = self.stream.read(4)
        # left_Brc80 = self.stream.read(4)
        # below_Brc80 = self.stream.read(4)
        # right_Brc80 = self.stream.read(4)

        self.index += 4
    
        return dxaGoal, dyaGoal, mx, my, bpp #, above_Brc80, left_Brc80, below_Brc80, right_Brc80
    
    
    def parse_OfficeArtFBSE(self):
        '''
        OfficeArtFBSE is made up of record header and 
            1 byte btWin32
            1 byte btMacOS
            16 byte MD4 hash of pixel data in BLIP
            1 ushort internal resource tag, must be 0xFF for external files
            1 uint size of BLIP data
            1 uint cRef, number of references to BLIP
            4 byte MSOFO struct
            1 byte unused1
            1 byte cbName, number of bytes in nameData, must be even and <= 0xFE
            1 byte unused2
            1 byte unused3
            nameData, Unicode NULL terminated string, name of BLIP
            OfficeArtBlip Record [MS-ODRAW] 2.2.23, poss types EMF, WMF, PICT, JPEG, PNG, DIB, TIFF, JPEG
        '''

        btWin32 = self.read_byte()
        btMacOS = self.read_byte()
        md4 = self.read_bytes(16)
        tag = self.read_word()
        blip_size = self.read_dword()
        cRef = self.read_dword()
        self.index += 4 # skip over MSOFO struct
        self.index += 1 # skip over unused1
        cbName = self.read_byte()
        self.index += 2 # skip over unused2 and unused3
        if cbName > 0:
            nameData = self.read_bytes(cbName)
        else:
            nameData = ""
    
        rec_ver, recInstance, recType, recLen = self.parse_OfficeArtRecordHeader()
        if recType == 0xf01a: 
            image_data = self.parse_img_type_1(recInstance, recLen)
        elif recType == 0xf01b: 
            image_data = self.parse_img_type_1(recInstance, recLen)
        elif recType == 0xf01c: 
            image_data = self.parse_img_type_1(recInstance, recLen)
        elif recType == 0xf01d or recType == 0xf02a: 
            image_data = self.parse_img_type_2(recInstance, recLen)
        elif recType == 0xf01e:
            image_data = self.parse_img_type_2(recInstance, recLen)
        elif recType == 0xf01f:
            image_data = self.parse_img_type_2(recInstance, recLen)
        elif recType == 0xf029:
            image_data = self.parse_img_type_2(recInstance, recLen)
    
        img_hash = SHA256.new()
        img_hash.update(image_data)
        self.img_info.append(img_hash.hexdigest())

        if self.save:
            with open("{}/{}".format(self.save, img_hash.hexdigest()), "w") as fo:
                fo.write(image_data)

    
        
    def parse_img_type_1(self, recInstance, recLen):
        '''
        A EMF, WMF, PICT record is made up of header and 
            16 byte rgbUid1, md4 of uncompressed BLIPFileData
            optional 16 byte rgbUid2
            34 byte OfficeArtMetafileHeader struct
            EMF, WMF, PICT data
        '''
        
        recLen -= 50
        rgbUid1 = self.read_bytes(16)
        if recInstance == 0x217 or recInstance == 0x3d5 or recInstance == 0x543:
            rgbUid2 = self.read_bytes(6)
            recLen -= 16
            
        
        OfficeArtMetafileHeader = self.read_bytes(34)
        
        EMFFileData = self.read_bytes(recLen)
    
        return EMFFileData
        
    
    
    def parse_img_type_2(self, recInstance, recLen):
        '''
        A PNG, JPEG, DIB, TIFF record is made up of header and 
            16 byte rgbUid1, md4 of uncompressed BLIPFileData
            optional 16 byte rgbUid2
            1 byte tag
            PNG, JPEG, DIB, TIFF data
        '''
        
        recLen -= 17 # recLen includes bytes and rgbUid1, need to remove these from the count
        rgbUid1 = self.read_bytes(16)
        if recInstance == 0x46b or recInstance == 0x6e1 or recInstance == 0x6e3 or recInstance == 0x6e5 or recInstance == 0x7a9: 
            rgbUid2 = self.read_bytes(16)
            recLen -= 16
            
        
        tag = self.read_byte()
        
        BLIPFileData = self.read_bytes(recLen)
    
        return BLIPFileData
        
    
    
    def parse_PICAndOfficeArtData(self, stream_end):
        # already read lcp, lcp = self.read_dword()
        cbHeader = self.read_word()
        if cbHeader != 0x44:
            return ""
    
        # parse mfpf struct
        mfpf_mm, _, _, _ = self.parse_mfpf()
        if mfpf_mm != 0x64 and mfpf_mm != 0x66: # must be 64 MM_SHAPE or 66_SHAPEFILE
            return "" # should I return more?
    
        # parse innerHeader
        _, _ = self.parse_innerHeader()

        # parse picmid struct
        dxaGoal, dyaGoal, mx, my, bpp = self.parse_picmid() # , above_Brc80, left_Brc80, below_Brc80, right_Brc80 

        cProps = self.read_word()
        if cProps != 0:
            return ""
    
        # if 66_SHAPEFILE read PicName
        if mfpf_mm == 0x66:
            # read PicName
            pass
    
        # believe we can just read records as they go
        while(self.index < stream_end):
            rec_ver, rec_instance, recType, recLen = self.parse_OfficeArtRecordHeader()
            if recType == 0xf004:
                self.index += recLen
                pass # this record contains shape records, but the records all contain the sam type of header
    
            elif recType == 0xf009:
                self.index += recLen
                pass # TODO
    
            elif recType == 0xf00a:
                self.index += recLen
                pass # TODO
                
            elif recType == 0xf00b:
                self.index += recLen
                pass # TODO
                
            elif recType == 0xf11d:
                self.index += recLen
                pass # TODO
                
            elif recType == 0xf121:
                self.index += recLen
                pass # TODO
                
            elif recType == 0xf122:
                self.index += recLen
                pass # TODO
                
            elif recType == 0xf010:
                self.index += recLen
                pass # TODO
                
            elif recType == 0xf007:
                self.parse_OfficeArtFBSE()

            else:
                self.index += recLen
    
            
        return "" # did not hit image data


AddPlugin(extract_and_hash_image)

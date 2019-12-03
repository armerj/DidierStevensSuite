#!/usr/bin/env python

__description__ = 'Extract image and hash it plugin for oledump.py'
__author__ = 'Jon Armer'
__version__ = '0.0.1'
__date__ = '2019/12/03'

"""

Source code put in public domain by Jon Armer, no Copyright
Use at your own risk

This plugin will attempt to extract image and hash it

Usage:
$ python oledump.py ../test_docs/image_in_doc.doc -p extract_img_plugin.py --pluginoptions save=../test_docs/extract_image.jpeg
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
    - Stop passing ole data as params
    - Add in other shape records
    - Return shape name
    - Add ability for multiple images
"""

import struct
from Crypto.Hash import SHA256


class extract_and_hash_image(cPluginParent):
    macroOnly = False

    name = 'Extract and sha256 hash image plugin. save image with --pluginoptions save=<location>'

    #  options is a string passed to --pluginoptions.
    def __init__(self, name, stream, options):
        # Storing the arguments for later use by Analyze method
        self.streamname = name
        self.stream = stream
        self.options = options
        self.save = ""
        self.index = 0

        self.ran = False

    # Method Analyze is called by oledump to let the plugin analyze the stream.
    # This method must return a list of strings: this is the plugin output to be displayed by oledump.
    # This method must also set object property ran to True to have oledump display output for this plugin.
    def Analyze(self):
        result = ""

        for option in self.options.split(','):
            if option.startswith("save"):
                self.save = option.split("=")[1]


        if self.stream and self.streamname == ['Data']:
            while(self.index < len(self.stream)):
                data_element_size = self.read_dword(self.stream)
                img_hash = self.parse_PICAndOfficeArtData(self.stream)
                if img_hash:
                    self.ran = True
                    return "sha256 hash is: {}".format(img_hash)

                self.index += data_element_size - 4
            

        return result

    
    def read_byte(self, ole_stream): 
        val = ord(ole_stream[self.index])
        self.index += 1
        return val

    def read_bytes(self, ole_stream, num):
        val = ole_stream[self.index:self.index + num]
        self.index += num
        return val

    def read_sword(self, ole_stream): # could use read bytes, and then do unpacking
        val = struct.unpack("<h", ole_stream[self.index:self.index + 2])[0]
        self.index += 2
        return val

    def read_sdword(self, ole_stream):
        val = struct.unpack("<i", ole_stream[self.index:self.index + 4])[0]
        self.index += 4
        return val

    def read_word(self, ole_stream):
        val = struct.unpack("<H", ole_stream[self.index:self.index + 2])[0]
        self.index += 2
        return val

    def read_dword(self, ole_stream):
        val = struct.unpack("<I", ole_stream[self.index:self.index + 4])[0]
        self.index += 4
        return val
    
    
    def parse_OfficeArtRecordHeader(self, ole_stream):
        '''
        A OfficeArtRecordHeader is 8 bytes and is made up of 
            1 nibble recVer, least significate nibble once ushort has been read
            3 nibble recInstance
            1 ushort recType
            1 uint recLen
        '''
    
        rec_ver_instance = self.read_word(ole_stream)
        recType = self.read_word(ole_stream)
        recLen = self.read_dword(ole_stream)
    
        return rec_ver_instance & 0xF, (rec_ver_instance & 0xFFF0) >> 4, recType, recLen
    
    
    
    def parse_mfpf(self, ole_stream):
        '''
        The mfpf struct is 8 bytes and is made up of
            1 ushort mm
            1 ushort xExt
            1 ushort yExt
            1 ushort swHMF
        '''
    
        mm = self.read_word(ole_stream)
        xExt = self.read_word(ole_stream)
        yExt = self.read_word(ole_stream)
        swHMF = self.read_word(ole_stream)
        
        return mm, xExt, yExt, swHMF
        
    
    def parse_innerHeader(self, ole_stream):
        '''
        The innerHeader struct is 14 bytes and is made up of 
            1 uint grf
            1 uint padding1
            1 ushort mmPM
            1 uint padding2
        '''
    
        grf = self.read_dword(ole_stream)
        self.index += 4
        mmPM = self.read_word(ole_stream)
        # padding2 = struct.unpack("<I", ole_stream.read(4))
        self.index += 4
    
        return grf, mmPM
        
    def parse_picmid(self, ole_stream):
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
    
        dxaGoal = self.read_sword(ole_stream)
        dyaGoal = self.read_sword(ole_stream)
        mx = self.read_word(ole_stream)
        my = self.read_word(ole_stream)
        self.index += 8
        self.index += 1
        bpp = self.read_byte(ole_stream)
        # can parse Brc80, but haven't added in 
        self.index += 16
        # above_Brc80 = ole_stream.read(4)
        # left_Brc80 = ole_stream.read(4)
        # below_Brc80 = ole_stream.read(4)
        # right_Brc80 = ole_stream.read(4)

        self.index += 4
    
        return dxaGoal, dyaGoal, mx, my, bpp #, above_Brc80, left_Brc80, below_Brc80, right_Brc80
    
    
    def parse_OfficeArtFBSE(self, ole_stream):
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
        
        btWin32 = self.read_byte(ole_stream)
        btMacOS = self.read_byte(ole_stream)
        md4 = self.read_bytes(ole_stream, 16)
        tag = self.read_word(ole_stream)
        blip_size = self.read_dword(ole_stream)
        cRef = self.read_dword(ole_stream)
        self.index += 4 # skip over MSOFO struct
        self.index += 1 # skip over unused1
        cbName = self.read_byte(ole_stream)
        self.index += 2 # skip over unused2 and unused3
        if cbName > 0:
            nameData = self.read_bytes(cbName)
        else:
            nameData = ""
    
        rec_ver, recInstance, recType, recLen = self.parse_OfficeArtRecordHeader(ole_stream)
        if recType == 0xf01a: 
            image_data = self.parse_emf(ole_stream, recInstance, recLen)
        elif recType == 0xf01b: 
            image_data = self.parse_wmf(ole_stream, recInstance, recLen)
        elif recType == 0xf01c: 
            image_data = self.parse_pict(ole_stream, recInstance, recLen)
        elif recType == 0xf01d or recType == 0xf02a: 
            image_data = self.parse_jpeg(ole_stream, recInstance, recLen)
        elif recType == 0xf01e:
            image_data = self.parse_png(ole_stream, recInstance, recLen)
        elif recType == 0xf01f:
            image_data = self.parse_dib(ole_stream, recInstance, recLen)
        elif recType == 0xf029:
            image_data = self.parse_tiff(ole_stream, recInstance, recLen)
    
        if self.save:
            with open(self.save, "w") as fo:
                fo.write(image_data)

        img_hash = SHA256.new()
        img_hash.update(image_data)
        return img_hash.hexdigest()
        
    
    def parse_pict(self, ole_stream, recInstance, recLen): # maybe I should combine emf, wmf, and pict parsers
        '''
        A PICT record is made up of header and 
            16 byte rgbUid1, md4 of uncompressed BLIPFileData
            optional 16 byte rgbUid2
            34 byte OfficeArtMetafileHeader struct
            PICT data
        '''
        
        recLen -= 50
        rgbUid1 = self.read_bytes(ole_stream, 16)
        if recInstance == 0x543:
            rgbUid2 = self.read_bytes(ole_stream, 16)
            recLen -= 16
            
        
        OfficeArtMetafileHeader = self.read_bytes(ole_stream, 34)
        
        PICTFileData = self.read_bytes(ole_stream, recLen)
    
        return PICTFileData
    
        
    def parse_emf(self, ole_stream, recInstance, recLen):
        '''
        A EMF record is made up of header and 
            16 byte rgbUid1, md4 of uncompressed BLIPFileData
            optional 16 byte rgbUid2
            34 byte OfficeArtMetafileHeader struct
            EMF data
        '''
        
        recLen -= 50
        rgbUid1 = self.read_bytes(ole_stream, 16)
        if recInstance == 0x3d5:
            rgbUid2 = self.read_bytes(ole_stream, 16)
            recLen -= 16
            
        
        OfficeArtMetafileHeader = self.read_bytes(ole_stream, 34)
        
        EMFFileData = self.read_bytes(ole_stream, recLen)
    
        return EMFFileData
        
    
    def parse_wmf(self, ole_stream, recInstance, recLen):
        '''
        A WMF record is made up of header and 
            16 byte rgbUid1, md4 of uncompressed BLIPFileData
            optional 16 byte rgbUid2
            34 byte OfficeArtMetafileHeader struct
            WMF data
        '''
        
        recLen -= 50
        rgbUid1 = self.read_bytes(ole_stream, 16)
        if recInstance == 0x217:
            rgbUid2 = self.read_bytes(ole_stream, 16)
            recLen -= 16
            
        
        OfficeArtMetafileHeader = self.read_bytes(ole_stream, 34)
        
        WMFFileData = self.read_bytes(ole_stream, recLen)
    
        return WMFFileData
    
    
    def parse_png(self, ole_stream, recInstance, recLen):
        '''
        A PNG record is made up of header and 
            16 byte rgbUid1, md4 of uncompressed BLIPFileData
            optional 16 byte rgbUid2
            1 byte tag
            PNG data
        '''
        
        recLen -= 17 # recLen includes bytes and rgbUid1, need to remove these from the count
        rgbUid1 = self.read_bytes(ole_stream, 16)
        if recInstance == 0x6e1:
            rgbUid2 = self.read_bytes(ole_stream, 16)
            recLen -= 16
            
        
        tag = self.read_byte(ole_stream)
        
        BLIPFileData = self.read_bytes(ole_stream, recLen)
    
        return BLIPFileData
        
    
    def parse_jpeg(self, ole_stream, recInstance, recLen):
        '''
        A JPEG record is made up of header and 
            16 byte rgbUid1, md4 of uncompressed BLIPFileData
            optional 16 byte rgbUid2
            1 byte tag
            JPEG data
        '''
        
        recLen -= 17 # recLen includes bytes and rgbUid1, need to remove these from the count
        rgbUid1 = self.read_bytes(ole_stream, 16)
        if recInstance == 0x46b or recInstance == 0x6e3:
            rgbUid2 = self.read_bytes(ole_stream, 16)
            recLen -= 16
            
        
        tag = self.read_byte(ole_stream)
        
        JPEGFileData = self.read_bytes(ole_stream, recLen)
    
        return JPEGFileData
        
    
    def parse_dib(self, ole_stream, recInstance, recLen):
        '''
        A DIB record is made up of header and 
            16 byte rgbUid1, md4 of uncompressed BLIPFileData
            optional 16 byte rgbUid2
            1 byte tag
            DIB data
        '''
        
        recLen -= 17 # recLen includes bytes and rgbUid1, need to remove these from the count
        rgbUid1 = self.read_bytes(ole_stream, 16)
        if recInstance == 0x7a9:
            rgbUid2 = self.read_bytes(ole_stream, 16)
            recLen -= 16
            
        
        tag = self.read_byte(ole_stream)
        
        DIBFileData = self.read_bytes(ole_stream, recLen)
    
        return DIBFileData
    
    
    def parse_tiff(self, ole_stream, recInstance, recLen):
        '''
        A TIFF record is made up of header and 
            16 byte rgbUid1, md4 of uncompressed BLIPFileData
            optional 16 byte rgbUid2
            1 byte tag
            TIFF data
        '''
        
        recLen -= 17 # recLen includes bytes and rgbUid1, need to remove these from the count
        rgbUid1 = self.read_bytes(ole_stream, 16)
        if recInstance == 0x6e5:
            rgbUid2 = self.read_bytes(ole_stream, 16)
            recLen -= 16
            
        
        tag = self.read_byte(ole_stream)
        
        TIFFFileData = self.read_bytes(ole_stream, recLen)
    
        return TIFFFileData
    
    
    def parse_PICAndOfficeArtData(self, ole_stream):
        # already read lcp, lcp = self.read_dword(ole_stream)
        cbHeader = self.read_word(ole_stream)
        if cbHeader != 0x44:
            return ""
    
        # parse mfpf struct
        mfpf_mm, _, _, _ = self.parse_mfpf(ole_stream)
        if mfpf_mm != 0x64 and mfpf_mm != 0x66: # must be 64 MM_SHAPE or 66_SHAPEFILE
            return "" # should I return more?
    
        # parse innerHeader
        _, _ = self.parse_innerHeader(ole_stream)

        # parse picmid struct
        dxaGoal, dyaGoal, mx, my, bpp = self.parse_picmid(ole_stream) # , above_Brc80, left_Brc80, below_Brc80, right_Brc80 

        cProps = self.read_word(ole_stream)
        if cProps != 0:
            return ""
    
        # if 66_SHAPEFILE read PicName
        if mfpf_mm == 0x66:
            # read PicName
            pass
    
        # believe we can just read records as they go
        while(self.index < len(ole_stream)):
            rec_ver, rec_instance, recType, recLen = self.parse_OfficeArtRecordHeader(ole_stream)
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
                return self.parse_OfficeArtFBSE(ole_stream)

            else:
                self.index += recLen
    
            
        return "" # did not hit image data


AddPlugin(extract_and_hash_image)

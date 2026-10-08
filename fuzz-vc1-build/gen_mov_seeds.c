/* Generate structured MOV/MP4 fuzzer seeds for target_dem_mov_fuzzer */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* MOV atom helpers */
static int pos = 0;
static uint8_t buf[65536];

static void write_u8(uint8_t v)  { buf[pos++] = v; }
static void write_u16(uint16_t v) { buf[pos++] = (v>>8); buf[pos++] = (v)&0xff; }
static void write_u32(uint32_t v) {
    buf[pos++] = (v>>24); buf[pos++] = (v>>16)&0xff;
    buf[pos++] = (v>>8)&0xff; buf[pos++] = v&0xff;
}
static void write_u64(uint64_t v) {
    write_u32((uint32_t)(v>>32)); write_u32((uint32_t)v);
}

/* Write a 4-byte atom type */
static void write_type(const char *t) {
    buf[pos++] = t[0]; buf[pos++] = t[1]; buf[pos++] = t[2]; buf[pos++] = t[3];
}

/* Start an atom, returns position of size field for patching */
static int start_atom(const char *type) {
    int size_pos = pos;
    pos += 4; /* skip size, will patch later */
    write_type(type);
    return size_pos;
}

/* Finish an atom, patch the size */
static void end_atom(int size_pos) {
    uint32_t size = pos - size_pos;
    buf[size_pos]   = (size>>24);
    buf[size_pos+1] = (size>>16)&0xff;
    buf[size_pos+2] = (size>>8)&0xff;
    buf[size_pos+3] = size&0xff;
}

/* Write full atom with content */
static int write_atom(const char *type, const uint8_t *data, int len) {
    int size_pos = start_atom(type);
    if (data && len > 0) {
        memcpy(buf + pos, data, len);
        pos += len;
    }
    end_atom(size_pos);
    return size_pos;
}

/* Helper: write 3 bytes (flags) */
static void write_u24(uint32_t v) {
    buf[pos++] = (v>>16)&0xff; buf[pos++] = (v>>8)&0xff; buf[pos++] = v&0xff;
}

/* Write ftyp atom */
static void write_ftyp(const char *brand, uint32_t version, const char *compat[]) {
    int sp = start_atom("ftyp");
    write_type(brand);
    write_u32(version);
    if (compat) {
        for (int i = 0; compat[i]; i++) {
            write_type(compat[i]);
        }
    }
    end_atom(sp);
}

/* Write mvhd atom (movie header, version 0) */
static void write_mvhd(void) {
    int sp = start_atom("mvhd");
    write_u8(0);  /* version */
    write_u24(0); /* flags */
    write_u32(0);  /* creation_time */
    write_u32(0);  /* modification_time */
    write_u32(1000); /* timescale */
    write_u32(10000); /* duration (10s) */
    write_u32(0x00010000); /* rate (1.0) */
    write_u16(0x0100); /* volume (1.0) */
    write_u16(0); /* reserved */
    write_u32(0); write_u32(0); /* reserved */
    /* matrix (36 bytes) */
    write_u32(0x00010000); write_u32(0); write_u32(0);
    write_u32(0); write_u32(0x00010000); write_u32(0);
    write_u32(0); write_u32(0); write_u32(0x40000000);
    write_u32(0); /* pre_defined */
    write_u32(0); /* pre_defined */
    write_u32(0); /* pre_defined */
    write_u32(0); /* pre_defined */
    write_u32(0); /* pre_defined */
    write_u32(0); /* pre_defined */
    write_u32(2); /* next_track_ID */
    end_atom(sp);
}

/* Write tkhd atom (track header, version 0) */
static void write_tkhd(uint32_t track_id, uint16_t width, uint16_t height) {
    int sp = start_atom("tkhd");
    write_u8(0);  /* version */
    write_u24(0x000003); /* flags: track_enabled | track_in_movie */
    write_u32(0);  /* creation_time */
    write_u32(0);  /* modification_time */
    write_u32(track_id); /* track_ID */
    write_u32(0);  /* reserved */
    write_u32(10000); /* duration */
    write_u32(0); write_u32(0); /* reserved */
    write_u16(0);  /* layer */
    write_u16(0);  /* alternate_group */
    write_u16(0);  /* volume */
    write_u16(0);  /* reserved */
    /* matrix (36 bytes) */
    write_u32(0x00010000); write_u32(0); write_u32(0);
    write_u32(0); write_u32(0x00010000); write_u32(0);
    write_u32(0); write_u32(0); write_u32(0x40000000);
    write_u32(width << 16);  /* width (fixed point) */
    write_u32(height << 16); /* height (fixed point) */
    end_atom(sp);
}

/* Write mdhd atom (media header, version 0) */
static void write_mdhd(void) {
    int sp = start_atom("mdhd");
    write_u8(0); write_u24(0);
    write_u32(0);  /* creation_time */
    write_u32(0);  /* modification_time */
    write_u32(24000); /* timescale */
    write_u32(240000); /* duration */
    write_u16(0x55C4); /* language (und) */
    write_u16(0);  /* quality */
    end_atom(sp);
}

/* Write hdlr atom */
static void write_hdlr(const char *handler_type) {
    int sp = start_atom("hdlr");
    write_u8(0); write_u24(0);
    write_u32(0);  /* pre_defined */
    write_type(handler_type);
    write_u32(0); write_u32(0); write_u32(0); /* reserved */
    buf[pos++] = 0; /* name (null terminated) */
    end_atom(sp);
}

/* Write stsd atom with minimal video sample entry */
static void write_stsd_video(const char *codec, uint16_t width, uint16_t height) {
    int sp = start_atom("stsd");
    write_u8(0); write_u24(0);
    write_u32(1);  /* entry_count */
    /* sample entry */
    int se_sp = start_atom(codec);
    write_u8(0); write_u24(0); /* reserved */
    write_u16(0); /* data_ref_index */
    write_u16(0); /* version + revision */
    write_type("ffmpeg"); /* vendor */
    write_u32(0); /* temporal_quality */
    write_u32(0); /* spatial_quality */
    write_u16(width); /* width */
    write_u16(height); /* height */
    write_u32(0x00480000); /* horiz_resolution (72 dpi) */
    write_u32(0x00480000); /* vert_resolution (72 dpi) */
    write_u32(0); /* data_size */
    write_u16(1); /* frame_count */
    /* compressor_name (32 bytes) */
    for (int i = 0; i < 32; i++) buf[pos++] = 0;
    write_u16(0x0018); /* depth */
    write_u16(0xFFFF); /* color_table_id */
    end_atom(se_sp);
    end_atom(sp);
}

/* Write stsd atom with minimal audio sample entry */
static void write_stsd_audio(const char *codec) {
    int sp = start_atom("stsd");
    write_u8(0); write_u24(0);
    write_u32(1);  /* entry_count */
    int se_sp = start_atom(codec);
    write_u8(0); write_u24(0);
    write_u16(1); /* data_ref_index */
    write_u16(0); /* version */
    write_u16(0); /* revision */
    write_u32(0); /* vendor */
    write_u16(2); /* channels */
    write_u16(16); /* sample_size */
    write_u16(0); /* compression_id */
    write_u16(0); /* packet_size */
    write_u32(44100 << 16); /* sample_rate (fixed point) */
    end_atom(se_sp);
    end_atom(sp);
}

/* Write stts atom (time to sample) */
static void write_stts(uint32_t count, uint32_t duration) {
    int sp = start_atom("stts");
    write_u8(0); write_u24(0);
    write_u32(1);  /* entry_count */
    write_u32(count);  /* sample_count */
    write_u32(duration); /* sample_duration */
    end_atom(sp);
}

/* Write stsc atom (sample to chunk) */
static void write_stsc(void) {
    int sp = start_atom("stsc");
    write_u8(0); write_u24(0);
    write_u32(1);  /* entry_count */
    write_u32(1);  /* first_chunk */
    write_u32(1);  /* samples_per_chunk */
    write_u32(1);  /* sample_description_index */
    end_atom(sp);
}

/* Write stsz atom (sample sizes) */
static void write_stsz(uint32_t count, uint32_t size) {
    int sp = start_atom("stsz");
    write_u8(0); write_u24(0);
    write_u32(size); /* sample_size (0=variable) */
    write_u32(count); /* sample_count */
    end_atom(sp);
}

/* Write stco atom (chunk offsets) */
static void write_stco(uint32_t offset) {
    int sp = start_atom("stco");
    write_u8(0); write_u24(0);
    write_u32(1);  /* entry_count */
    write_u32(offset); /* chunk_offset */
    end_atom(sp);
}

/* Write smhd atom (sound media header) */
static void write_smhd(void) {
    int sp = start_atom("smhd");
    write_u8(0); write_u24(0);
    write_u16(0); /* balance */
    write_u16(0); /* reserved */
    end_atom(sp);
}

/* Write vmhd atom (video media header) */
static void write_vmhd(void) {
    int sp = start_atom("vmhd");
    write_u8(0); write_u24(1); /* flags */
    write_u16(0); /* graphicsmode */
    write_u16(0); write_u16(0); write_u16(0); /* opcolor */
    end_atom(sp);
}

/* Write dinf/dref atom */
static void write_dinf(void) {
    int sp = start_atom("dinf");
    int dref_sp = start_atom("dref");
    write_u8(0); write_u24(0);
    write_u32(1); /* entry_count */
    int url_sp = start_atom("url ");
    write_u24(1); /* flags = self-contained */
    end_atom(url_sp);
    end_atom(dref_sp);
    end_atom(sp);
}

/* Write a minimal video track */
static void write_video_track(uint16_t width, uint16_t height, const char *codec) {
    int trak_sp = start_atom("trak");
    write_tkhd(1, width, height);
    
    int mdia_sp = start_atom("mdia");
    write_mdhd();
    write_hdlr("vide");
    
    int minf_sp = start_atom("minf");
    write_vmhd();
    write_dinf();
    
    int stbl_sp = start_atom("stbl");
    write_stsd_video(codec, width, height);
    write_stts(10, 1000);
    write_stsc();
    write_stsz(10, 1024);
    write_stco(0); /* will be wrong but that's ok for fuzzing */
    end_atom(stbl_sp);
    
    end_atom(minf_sp);
    end_atom(mdia_sp);
    end_atom(trak_sp);
}

/* Write a minimal audio track */
static void write_audio_track(const char *codec) {
    int trak_sp = start_atom("trak");
    write_tkhd(2, 0, 0);
    
    int mdia_sp = start_atom("mdia");
    write_mdhd();
    write_hdlr("soun");
    
    int minf_sp = start_atom("minf");
    write_smhd();
    write_dinf();
    
    int stbl_sp = start_atom("stbl");
    write_stsd_audio(codec);
    write_stts(10, 1024);
    write_stsc();
    write_stsz(10, 512);
    write_stco(0);
    end_atom(stbl_sp);
    
    end_atom(minf_sp);
    end_atom(mdia_sp);
    end_atom(trak_sp);
}

/* Write configuration area for target_dem_fuzzer (IO_FLAT=0) */
static int write_config(uint8_t *config, int io_buffer_size, int seekable,
                         int64_t filesize, const char *filename) {
    int c = 0;
    /* First 1024 bytes: config */
    config[c++] = (io_buffer_size) & 0xff;
    config[c++] = (io_buffer_size >> 8) & 0xff;
    config[c++] = (io_buffer_size >> 16) & 0xff;
    config[c++] = (io_buffer_size >> 24) & 0xff;  /* io_buffer_size LE */
    config[c++] = seekable ? 1 : 0;  /* flags */
    c++; c++; c++; /* padding */
    /* filesize LE64 */
    for (int i = 0; i < 8; i++) config[c++] = (filesize >> (i*8)) & 0xff;
    /* interrupt_counter LE32 */
    config[c++] = 0xFF; config[c++] = 0xFF; config[c++] = 0xFF; config[c++] = 0x7F;
    /* rest of config area: zeros */
    while (c < 1024) config[c++] = 0;
    
    /* Second 1024 bytes: filename */
    c = 1024;
    if (filename) {
        int len = strlen(filename);
        if (len > 1024) len = 1024;
        memcpy(config + c, filename, len);
    }
    c += 1024;
    
    return 2048;
}

static int write_seed(const char *outfile) {
    uint8_t config[2048];
    int mov_size = pos;
    int64_t filesize = mov_size;
    write_config(config, 32768, 1, filesize, "fuzz.mov");
    
    FILE *f = fopen(outfile, "wb");
    if (!f) { fprintf(stderr, "Cannot open %s\n", outfile); return -1; }
    fwrite(buf, 1, mov_size, f);
    fwrite(config, 1, sizeof(config), f);
    fclose(f);
    printf("  Written: %s (%d bytes = %d MOV + 2048 config)\n", outfile, mov_size + 2048, mov_size);
    return 0;
}

int main(int argc, char **argv) {
    const char *basedir = argc > 1 ? argv[1] : "c:\\Users\\Administrator\\Desktop\\1\\8-6\\FFmpeg-release-8.1\\fuzz-corpus-mov";
    char path[512];
    
    printf("Generating structured MOV/MP4 fuzzer seeds...\n");
    
    /* Seed 1: Minimal valid MP4 with ftyp+moov+mdat */
    pos = 0;
    {
        const char *compat[] = {"isom", "mp41", NULL};
        write_ftyp("isom", 0x200, compat);
        int moov_sp = start_atom("moov");
        write_mvhd();
        write_video_track(320, 240, "avc1");
        end_atom(moov_sp);
        int mdat_sp = start_atom("mdat");
        /* some dummy media data */
        for (int i = 0; i < 64; i++) buf[pos++] = 0;
        end_atom(mdat_sp);
        snprintf(path, sizeof(path), "%s\\seed_mov_mp4_avc1.bin", basedir);
        write_seed(path);
    }
    
    /* Seed 2: MOV with H.265/HEVC */
    pos = 0;
    {
        const char *compat[] = {"isom", NULL};
        write_ftyp("isom", 0, compat);
        int moov_sp = start_atom("moov");
        write_mvhd();
        write_video_track(640, 480, "hvc1");
        end_atom(moov_sp);
        int mdat_sp = start_atom("mdat");
        for (int i = 0; i < 128; i++) buf[pos++] = (uint8_t)(rand() % 256);
        end_atom(mdat_sp);
        snprintf(path, sizeof(path), "%s\\seed_mov_hevc.bin", basedir);
        write_seed(path);
    }
    
    /* Seed 3: MOV with audio+video */
    pos = 0;
    {
        const char *compat[] = {"isom", "mp42", NULL};
        write_ftyp("mp42", 0, compat);
        int moov_sp = start_atom("moov");
        write_mvhd();
        write_video_track(192, 128, "avc1");
        write_audio_track("mp4a");
        end_atom(moov_sp);
        int mdat_sp = start_atom("mdat");
        for (int i = 0; i < 256; i++) buf[pos++] = (uint8_t)(rand() % 256);
        end_atom(mdat_sp);
        snprintf(path, sizeof(path), "%s\\seed_mov_av.bin", basedir);
        write_seed(path);
    }
    
    /* Seed 4: QuickTime MOV (moov before mdat) */
    pos = 0;
    {
        write_ftyp("qt  ", 0x20070900, NULL);
        int moov_sp = start_atom("moov");
        write_mvhd();
        write_video_track(320, 240, "avc1");
        end_atom(moov_sp);
        int mdat_sp = start_atom("mdat");
        for (int i = 0; i < 64; i++) buf[pos++] = 0;
        end_atom(mdat_sp);
        snprintf(path, sizeof(path), "%s\\seed_mov_qt.bin", basedir);
        write_seed(path);
    }
    
    /* Seed 5: MOV with multiple tracks */
    pos = 0;
    {
        const char *compat[] = {"isom", NULL};
        write_ftyp("isom", 0, compat);
        int moov_sp = start_atom("moov");
        write_mvhd();
        /* video track 1 */
        write_video_track(1280, 720, "avc1");
        /* audio track */
        write_audio_track("mp4a");
        end_atom(moov_sp);
        int mdat_sp = start_atom("mdat");
        for (int i = 0; i < 512; i++) buf[pos++] = (uint8_t)(rand() % 256);
        end_atom(mdat_sp);
        snprintf(path, sizeof(path), "%s\\seed_mov_hd.bin", basedir);
        write_seed(path);
    }
    
    /* Seed 6: 3GP format */
    pos = 0;
    {
        const char *compat[] = {"3gp4", "3gp5", NULL};
        write_ftyp("3gp4", 0x200, compat);
        int moov_sp = start_atom("moov");
        write_mvhd();
        write_video_track(176, 144, "avc1");
        write_audio_track("samr");
        end_atom(moov_sp);
        int mdat_sp = start_atom("mdat");
        for (int i = 0; i < 64; i++) buf[pos++] = (uint8_t)(rand() % 256);
        end_atom(mdat_sp);
        snprintf(path, sizeof(path), "%s\\seed_mov_3gp.bin", basedir);
        write_seed(path);
    }
    
    /* Seed 7: MOV with VC-1 video */
    pos = 0;
    {
        write_ftyp("qt  ", 0, NULL);
        int moov_sp = start_atom("moov");
        write_mvhd();
        write_video_track(320, 240, "vc-1");
        end_atom(moov_sp);
        int mdat_sp = start_atom("mdat");
        for (int i = 0; i < 64; i++) buf[pos++] = (uint8_t)(rand() % 256);
        end_atom(mdat_sp);
        snprintf(path, sizeof(path), "%s\\seed_mov_vc1.bin", basedir);
        write_seed(path);
    }
    
    /* Seed 8: Minimal ftyp-only (edge case) */
    pos = 0;
    {
        write_ftyp("isom", 0, NULL);
        snprintf(path, sizeof(path), "%s\\seed_mov_minimal.bin", basedir);
        write_seed(path);
    }
    
    /* Seed 9: MOV with wide atom (64-bit size) */
    pos = 0;
    {
        const char *compat[] = {"isom", NULL};
        write_ftyp("isom", 0, compat);
        int moov_sp = start_atom("moov");
        write_mvhd();
        /* small track */
        int trak_sp = start_atom("trak");
        write_tkhd(1, 64, 64);
        int mdia_sp = start_atom("mdia");
        write_mdhd();
        write_hdlr("vide");
        int minf_sp = start_atom("minf");
        write_vmhd();
        int stbl_sp = start_atom("stbl");
        write_stsd_video("avc1", 64, 64);
        write_stts(1, 1000);
        write_stsc();
        write_stsz(1, 100);
        write_stco(0);
        end_atom(stbl_sp);
        end_atom(minf_sp);
        end_atom(mdia_sp);
        end_atom(trak_sp);
        end_atom(moov_sp);
        snprintf(path, sizeof(path), "%s\\seed_mov_tiny.bin", basedir);
        write_seed(path);
    }
    
    /* Seed 10: MOV with edts/elst atoms (edit list) */
    pos = 0;
    {
        const char *compat[] = {"isom", "mp41", NULL};
        write_ftyp("isom", 0, compat);
        int moov_sp = start_atom("moov");
        write_mvhd();
        int trak_sp = start_atom("trak");
        write_tkhd(1, 320, 240);
        /* edts atom */
        int edts_sp = start_atom("edts");
        int elst_sp = start_atom("elst");
        write_u8(0); write_u24(0);
        write_u32(1); /* entry_count */
        write_u32(10000); /* segment_duration */
        write_u32(0); /* media_time */
        write_u16(1); /* media_rate_integer */
        write_u16(0); /* media_rate_fraction */
        end_atom(elst_sp);
        end_atom(edts_sp);
        int mdia_sp = start_atom("mdia");
        write_mdhd();
        write_hdlr("vide");
        int minf_sp = start_atom("minf");
        write_vmhd();
        write_dinf();
        int stbl_sp = start_atom("stbl");
        write_stsd_video("avc1", 320, 240);
        write_stts(10, 1000);
        write_stsc();
        write_stsz(10, 1024);
        write_stco(0);
        end_atom(stbl_sp);
        end_atom(minf_sp);
        end_atom(mdia_sp);
        end_atom(trak_sp);
        end_atom(moov_sp);
        snprintf(path, sizeof(path), "%s\\seed_mov_edts.bin", basedir);
        write_seed(path);
    }
    
    printf("Done. 10 structured MOV seeds generated.\n");
    return 0;
}
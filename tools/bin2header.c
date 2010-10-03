/* raw2payload. Convert our raw PPC code into a fancy C header */

#include <stdio.h>
#include <string.h>

static const char ifdef_guard_header[] = \
  "#ifndef __%s__\n" \
  "#define __%s__\n\n";

static const char ifdef_guard_footer[] = "\n#endif\n";

static const char array_header[] = "static const char %s[] = {\n ";

static const char array_footer[] = "\n};\n\n";

static const char macro_header[] = "#define %s_macro \\\n ";

static const char macro_footer[] = "\n";

int main(int argc, char **argv)
{
  char buf[256];
  FILE *fi, *fo;
  int i, idx, r;

  if (argc < 4) {
    fprintf(stderr, "Usage: %s <raw> <c header> <array name>\n", argv[0]);
    return -1;
  }

  fi = fopen(argv[1], "rb");
  if (fi == NULL) {
    perror(argv[1]);
    return -2;
  }

  fo = fopen(argv[2], "w");
  if (fo == NULL) {
    perror(argv[2]);
    return -3;
  }

  fprintf(fo, ifdef_guard_header, argv[3], argv[3]);
  fprintf(fo, array_header, argv[3]);

  idx = 0;
  while ((r = fread(buf, 1, sizeof(buf), fi)) > 0) {
    for (i = 0; i < r; i++) {
      fprintf(fo, " 0x%.2x,", buf[i] & 0xff);
      if (++idx % 8 == 0)
        fprintf(fo, "\n ");
    }
  }

  fprintf(fo, "%s", array_footer);

  fseek(fi, 0, SEEK_SET);

  fprintf(fo, macro_header, argv[3]);

  idx = 0;
  while ((r = fread(buf, 1, sizeof(buf), fi)) > 0) {
    for (i = 0; i < r; i++) {
      fprintf(fo, " 0x%.2x,", buf[i] & 0xff);
      if (++idx % 8 == 0)
        fprintf(fo, " \\\n ");
    }
  }

  fprintf(fo, macro_footer);
  fprintf(fo, ifdef_guard_footer);

  fclose(fi);
  fclose(fo);
  fprintf(stdout, "Header %s generated.\n", argv[3]);
  return 0;
}

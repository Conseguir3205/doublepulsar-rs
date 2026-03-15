SECTIONS
{
    . = 0x0000;

    .text :
    {
        *( .text$A );
        *( .text$B );
        *( .text$C );
        *( .text$D );
        *( .text$E );
        *( .text$F );
        *( .text );
        *( .text.* );
        *( .rdata* );
        *( .data* );
        *( .idata* );
        *( .CRT* );
        *( .tls* );
        *( .ctors* );
        *( .edata* );
        KEEP( *(.text$ZZ) );
    }

    /* Discard exception handling and debug sections */
    /DISCARD/ :
    {
        *(.pdata);
        *(.xdata);
        *(.debug*);
        *(.eh_frame);
        *(.note*);
        *(.comment*);
    }
}

#!/usr/bin/env python
# -*- coding: utf-8 -*-

def replace_free(pt):
    '''
    .text:080485B8                 push    eax             ; format
    .text:080485B9                 call    _printf
    .text:080485BE                 add     esp, 10h
    '''
    printf_addr = 0x80485B9
    new_printf = pt.inject(c = r'''
    void fix_printf(char *fmt)
    {
        for(int i = 0; i < strlen(fmt) - 1; i++)
        {
            if(fmt[i] == 'h' && fmt[i + 1] == 'n')
            {
                fmt[i + 1] = 'h';
            }
        }
    }
    ''')

    pt.hook(printf_addr, new_printf)

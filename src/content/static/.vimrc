set nocompatible              " be iMproved, required
filetype off                  " required

set hlsearch
set autoindent
set nocompatible
set fileformats=unix,dos,mac

syntax on
filetype on

set number
set showmatch
set shiftwidth=2
set softtabstop=2
set tabstop=2
set completeopt=menu,longest,preview
set wildignore=*.o,*~,*.pyc

" This beauty remembers where you were the last time you edited the file, and returns to the same position.
au BufReadPost * if line("'\"") > 0|if line("'\"") <= line("$")|exe("norm '\"")|else|exe "norm $"|endif|endif
		"
" Highlight JSON as javascript -- usefull if you don't want to load json.vim
autocmd BufNewFile,BufRead *.json set ft=javascript

"Trim trailing whitespace in javascript files
autocmd BufWritePre *.js normal m`:%s/\s\+$//e ``

"Indentation
set smartindent
set autoindent
set expandtab
set softtabstop=2
set shiftwidth=2
filetype on

map <F4> :cn<CR>
map <F3> :cp<CR>
map <F7> :mak<CR>
map <F8> :mak clean<CR>
map <F9> :mak test<CR>

let c_no_curly_error=1

set matchpairs+=<:>

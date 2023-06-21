/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2010  Free Software Foundation, Inc.
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <config-util.h>

void EXPORT_FUNC (SDL_Quit) (void);
void EXPORT_FUNC (SDL_Init) (void);
void EXPORT_FUNC (SDL_GetError) (void);
#ifdef HAVE_SDL2
void EXPORT_FUNC (SDL_CreateWindow) (void);
void EXPORT_FUNC (SDL_GetWindowSurface) (void);
void EXPORT_FUNC (SDL_CreateRenderer) (void);
void EXPORT_FUNC (SDL_CreateRGBSurface) (void);
void EXPORT_FUNC (SDL_CreateTexture) (void);
void EXPORT_FUNC (SDL_UpdateTexture) (void);
void EXPORT_FUNC (SDL_SetPaletteColors) (void);
void EXPORT_FUNC (SDL_RenderClear) (void);
void EXPORT_FUNC (SDL_RenderCopy) (void);
void EXPORT_FUNC (SDL_RenderPresent) (void);
#else
void EXPORT_FUNC (SDL_Flip) (void);
void EXPORT_FUNC (SDL_SetColors) (void);
void EXPORT_FUNC (SDL_SetVideoMode) (void);
#endif

import { NextResponse, type NextRequest } from 'next/server';

import { verifyAuth } from './lib/auth';

export async function middleware(req: NextRequest) {
  // get token form user
  const token = req.cookies.get('user-token')?.value;

  // validate if the user is authenticated
  const verifiedToken =
    token &&
    (await verifyAuth(token).catch((err) => {
      console.log(err);
    }));

  // check if the user is already authenticated and go to the login page
  if (req.nextUrl.pathname.startsWith('/login') && !verifiedToken) {
    return;
  }

  const url = req.url;

  if (url.includes('/login') && verifiedToken) {
    return NextResponse.redirect(new URL('/dashboard', req.url));
  }

  // check if the user is not authenticated
  if (!verifiedToken) {
    return NextResponse.redirect(new URL('/login', req.url));
  }
}

export const config = {
  matcher: ['/dashboard', '/login'],
};

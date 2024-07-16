import { Lucia } from "lucia"
import { BetterSqlite3Adapter } from '@lucia-auth/adapter-sqlite'
import { cookies } from "next/headers";
import db from "./db";

const adapter = new BetterSqlite3Adapter(db, {
    user: 'users',
    session: 'sessions'
});

const lucia = new Lucia(adapter, {
    sessionCookie: {
        expires: false,
        attributes: {
            secure: process.env.NODE_ENV === 'production'
        }
    }
})

export async function createAuthSession(userId) {
    const session = await lucia.createSession(userId, {})
    const sessionCookie = lucia.createSessionCookie(session.id)
    cookies().set(sessionCookie.name,
        sessionCookie.value,
        sessionCookie.attributes)
}

export async function verifyAuth() {
    const sessionCookie = cookies().get(lucia.sessionCookieName)

    if (!sessionCookie) {
        return {
            user: null,
            session: null
        }
    }

    const sessionID = sessionCookie.value

    if (!sessionID) {
        return {
            user: null,
            session: null
        }
    }

    const result = lucia.validateSession(sessionID)

    try {
        if (result.session && (await result).session.fresh) {
            const sessionCookie = lucia.createSessionCookie(result.session.id)
            cookies().set(sessionCookie.name,
                sessionCookie.value,
                sessionCookie.attributes)
        }
        if (!result.session) {
            const sessionCookie = lucia.createBlankSessionCookie()
            cookies().set(sessionCookie.name,
                sessionCookie.value,
                sessionCookie.attributes)
        }

    } catch (error) {

    }

    return result
}

export async function destroySession() {
    const { session } = await verifyAuth()

    if (!session) {
        return {
            error: 'Unauthorized!'
        }
    }

    await lucia.invalidateSession(session.id)

    const sessionCookie = lucia.createBlankSessionCookie()
    cookies().set(sessionCookie.name,
        sessionCookie.value,
        sessionCookie.attributes)

}
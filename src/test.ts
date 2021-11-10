import { MiddlewareFn } from 'type-graphql';
import * as jwt from 'jsonwebtoken';
export interface UserTokenInterface {
	id: number;
	email: string;
	phone: string;
	accessCode: string;
	admin: boolean;
	superAdmin: boolean;
	status: boolean;
	workerId: number;
	firstName: string;
	lastName: string;
	supervisorAssignedAgencies: string[];
	jwtExpired: Date;
	roles: { id: number; roleName: string };
	permissions: string[];
}

const defaultAuthHeader = 'authorization';

export const GQLAuthGuard: MiddlewareFn = async ({ info, context, args }, next) => {
	const token = fromAuthHeaderAsBearerToken(context);
	const auth = <UserTokenInterface>jwt.verify(token, process.env.JWT_SECRET);

	if (!auth?.status) {
		throw new Error('Authorization failed.');
	}
	if (new Date(new Date().toUTCString().slice(0, -4)) > new Date(auth?.jwtExpired)) {
		throw new Error('Authorization failed.');
	}
	context['user'] = auth;

	await next();
};

function fromAuthHeaderAsBearerToken(context) {
	let token: string = null;
	if (context.headers[defaultAuthHeader]) {
		const authParams = parseAuthHeader(context.headers[defaultAuthHeader]);
		if (authParams && 'bearer' === authParams.scheme.toLowerCase()) {
			token = authParams.value;
		}
	}
	return token;
}

function parseAuthHeader(hdrValue): any | null {
	const re = /(\S+)\s+(\S+)/;
	if (typeof hdrValue !== 'string') {
		return null;
	}
	const matches = hdrValue.match(re);
	return matches && { scheme: matches[1], value: matches[2] };
}

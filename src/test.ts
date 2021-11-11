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

	if ((auth && !auth.status) || !auth) {
		throw new Error('Authorization failed.');
	}
	if (new Date(new Date().toUTCString().slice(0, -4)) > new Date(auth.jwtExpired)) {
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
export enum Role {
	Admin = 'admin',
	SuperAdmin = 'superAdmin',
	Supervisor = 'superVisor',
	AdminRoleView = 'admin.role.view',
	AdminRoleEdit = 'admin.role.edit',
	AdminRoleCreate = 'admin.role.create',
	AdminRoleDelete = 'admin.role.delete',
	AdminWorkerView = 'admin.worker.view',
	AdminWorkerEdit = 'admin.worker.edit',
	AdminWorkerCreate = 'admin.worker.create',
	AdminWorkerDelete = 'admin.worker.delete',
	AdminAgencyView = 'admin.agency.view',
	AdminAgencyCreate = 'admin.agency.create',
	AdminAgencyEdit = 'admin.agency.edit',
	AdminAgencyDelete = 'admin.agency.delete',
	AdminPositionView = 'admin.position.view',
	AdminPositionEdit = 'admin.position.edit',
	AdminPositionCreate = 'admin.position.create',
	AdminPositionDelete = 'admin.position.delete',
	AdminPunchList = 'admin.punch.list',
	AdminPunchCreate = 'admin.punch.create',
	AdminPunchEdit = 'admin.punch.edit',
	AdminPunchDelete = 'admin.punch.delete',
	AdminSupervisorView = 'admin.supervisor.view',
	AdminSupervisorEdit = 'admin.supervisor.edit',
	AdminSupervisorSummaryView = 'admin.supervisor.summary.view',
}
export const GQLUserRole = (permissionNames: string | string[]): MiddlewareFn => {
	return async ({ info, context, args }, next) => {
		// Throw an error if JWT verification fault.
		if (!context['user']) throw new Error('Permission denied.');
		// Check if roleName is string type.
		if (typeof permissionNames === 'string') {
			try {
				if (permissionNames === Role.SuperAdmin) {
					if (!context['user'][permissionNames]) throw new Error('Permission denied.');
				} else {
					if (!context['user']['permissions'].find((permission) => permission === permissionNames))
						throw new Error('Permission denied.');
				}
			} catch {
				throw new Error('Permission denied.');
			}
		} else {
			try {
				// If roleName array of strings.
				const permissions = permissionNames.map((role: string) => {
					if (role === Role.SuperAdmin) {
						return !!context['user'][role];
					} else {
						return !!context['user']['permissions'].find((permission) => permission === role);
					}
				});
				if (!permissions.find((permission: boolean) => permission)) throw new Error('Permission denied.');
			} catch {
				throw new Error('Permission denied.');
			}
		}

		return await next();
	};
}


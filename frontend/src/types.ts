export type Role='student'|'researcher'|'administrator'
export interface User{id:string;email:string;full_name:string;organization:string;role:Role;is_active:boolean}
export interface Project{id:string;name:string;description:string;scope:string;status:string;owner_id:string;created_at:string}
export interface Finding{id:string;project_id:string;asset_id?:string;asset:string;asset_ip?:string;title:string;description:string;port?:number;service?:string;severity:string;confidence:number;evidence:string;remediation:string;status:string;risk_score:number;created_at:string;analyst_notes?:string}


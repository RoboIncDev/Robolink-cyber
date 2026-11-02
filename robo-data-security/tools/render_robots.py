import sys, mujoco, numpy as np
from PIL import Image, ImageDraw
R="src/soma_retargeter/assets/robotics/"
MODELS={"x2-ultra":"agibot/x2/desc/agibot_x2ultra.urdf","a3":"agibot/a3/desc/agibot-a3t3.urdf","g1":"unitree/g1/desc/mjcf/g1_29dof_rev_1_0.xml"}
def tris(m,d):
    out=[]
    for g in range(m.ngeom):
        if m.geom_type[g]!=mujoco.mjtGeom.mjGEOM_MESH: continue
        if m.geom_group[g]>=3 or (m.geom_contype[g]!=0 and m.geom_conaffinity[g]!=0 and m.geom_group[g]==3): continue
        mid=m.geom_dataid[g]; v0,vn=m.mesh_vertadr[mid],m.mesh_vertnum[mid]; f0,fn=m.mesh_faceadr[mid],m.mesh_facenum[mid]
        V=m.mesh_vert[v0:v0+vn]; F=m.mesh_face[f0:f0+fn]
        W=V@d.geom_xmat[g].reshape(3,3).T+d.geom_xpos[g]; out.append(W[F])
    return np.concatenate(out)
def render(name,W=520,H=900,ss=2,az=35,el=8):
    m=mujoco.MjModel.from_xml_path(R+MODELS[name]); d=mujoco.MjData(m); mujoco.mj_forward(m,d)
    T=tris(m,d); T=T-np.array([0,0,T[...,2].min()])           # feet on z=0
    a=np.radians(az); e=np.radians(el)
    Rz=np.array([[np.cos(a),-np.sin(a),0],[np.sin(a),np.cos(a),0],[0,0,1]])
    # camera looks along +y after rotation; x right, z up
    P=T@Rz.T; P=P[...,[0,2,1]]; ce=np.array([[1,0,0],[0,np.cos(e),-np.sin(e)],[0,np.sin(e),np.cos(e)]]); P=P@ce.T
    N=np.cross(P[:,1]-P[:,0],P[:,2]-P[:,0]); L=np.linalg.norm(N,axis=1); ok=L>1e-12; P,N,L=P[ok],N[ok],L[ok]; N/=L[:,None]
    keep=N[:,2]<0; P,N=P[keep],N[keep]                           # back-face culling (outward STL winding)
    light=np.array([-0.45,-0.85,0.5]); light/=np.linalg.norm(light)
    sh=np.clip(N@light,0,1)*0.6+0.34
    lo=P.reshape(-1,3).min(0); hi=P.reshape(-1,3).max(0); sc=min((W*ss*0.9)/(hi[0]-lo[0]),(H*ss*0.94)/(hi[1]-lo[1]))
    cx=(lo[0]+hi[0])/2; X=(P[...,0]-cx)*sc+W*ss/2; Y=H*ss*0.97-(P[...,1]-lo[1])*sc
    order=np.argsort(-P[...,2].mean(1))                        # far first
    im=Image.new("RGBA",(W*ss,H*ss),(0,0,0,0)); dr=ImageDraw.Draw(im)
    for i in order:
        g=int(255*sh[i]); dr.polygon([(X[i,0],Y[i,0]),(X[i,1],Y[i,1]),(X[i,2],Y[i,2])],fill=(g,int(g*1.0),int(g*1.03),255))
    return im.resize((W,H),Image.LANCZOS), (hi[1]-lo[1])
if __name__=="__main__":
    for n in sys.argv[1:]:
        im,h=render(n); im.save(f"{n}.png"); print(n,im.getbbox(),"height m (model units):",round(h,3))
